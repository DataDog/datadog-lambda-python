import unittest
import json

try:
    from unittest.mock import MagicMock, patch, call
except ImportError:
    from mock import MagicMock, patch, call

from ddtrace.helpers import get_correlation_ids

from datadog_lambda.constants import SamplingPriority, TraceHeader, XraySubsegment
from datadog_lambda.tracing import (
    extract_dd_trace_context,
    create_dd_dummy_metadata_subsegment,
    create_function_execution_span,
    get_dd_trace_context,
    set_correlation_ids,
    _convert_xray_trace_id,
    _convert_xray_entity_id,
    _convert_xray_sampling,
)

function_arn = "arn:aws:lambda:us-west-1:123457598159:function:python-layer-test"


class ClientContext(object):
    def __init__(self, custom=None):
        self.custom = custom


def get_mock_context(
    aws_request_id="request-id-1",
    memory_limit_in_mb="256",
    invoked_function_arn=function_arn,
    function_version="1",
    custom=None,
):
    lambda_context = MagicMock()
    lambda_context.aws_request_id = aws_request_id
    lambda_context.memory_limit_in_mb = memory_limit_in_mb
    lambda_context.invoked_function_arn = invoked_function_arn
    lambda_context.function_version = function_version
    lambda_context.client_context = ClientContext(custom)
    return lambda_context


class TestExtractAndGetDDTraceContext(unittest.TestCase):
    def setUp(self):
        global dd_tracing_enabled
        dd_tracing_enabled = False
        patcher = patch("datadog_lambda.tracing.xray_recorder")
        self.mock_xray_recorder = patcher.start()
        self.mock_xray_recorder.get_trace_entity.return_value = MagicMock(
            id="ffff", trace_id="1111", sampled=True
        )
        self.mock_current_subsegment = MagicMock()
        self.mock_xray_recorder.current_subsegment.return_value = (
            self.mock_current_subsegment
        )
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.tracing.is_lambda_context")
        self.mock_is_lambda_context = patcher.start()
        self.mock_is_lambda_context.return_value = True
        self.addCleanup(patcher.stop)

    def tearDown(self):
        global dd_tracing_enabled
        dd_tracing_enabled = False

    def test_without_datadog_trace_headers(self):
        lambda_ctx = get_mock_context()
        ctx, source = extract_dd_trace_context({}, lambda_ctx)
        self.assertEqual(source, "xray")
        self.assertDictEqual(
            ctx, {"trace-id": "4369", "parent-id": "65535", "sampling-priority": "2"},
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "4369",
                TraceHeader.PARENT_ID: "65535",
                TraceHeader.SAMPLING_PRIORITY: "2",
            },
            {},
        )

    def test_with_incomplete_datadog_trace_headers(self):
        lambda_ctx = get_mock_context()
        ctx, source = extract_dd_trace_context(
            {"headers": {TraceHeader.TRACE_ID: "123", TraceHeader.PARENT_ID: "321"}},
            lambda_ctx,
        )
        self.assertEqual(source, "xray")
        self.assertDictEqual(
            ctx, {"trace-id": "4369", "parent-id": "65535", "sampling-priority": "2"},
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "4369",
                TraceHeader.PARENT_ID: "65535",
                TraceHeader.SAMPLING_PRIORITY: "2",
            },
        )

    def test_with_complete_datadog_trace_headers(self):
        lambda_ctx = get_mock_context()
        ctx, source = extract_dd_trace_context(
            {
                "headers": {
                    TraceHeader.TRACE_ID: "123",
                    TraceHeader.PARENT_ID: "321",
                    TraceHeader.SAMPLING_PRIORITY: "1",
                }
            },
            lambda_ctx,
        )
        self.assertEqual(source, "event")
        self.assertDictEqual(
            ctx, {"trace-id": "123", "parent-id": "321", "sampling-priority": "1"},
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "123",
                TraceHeader.PARENT_ID: "65535",
                TraceHeader.SAMPLING_PRIORITY: "1",
            },
        )
        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_xray_recorder.begin_subsegment.assert_called()
        self.mock_current_subsegment.put_metadata.assert_called_with(
            XraySubsegment.TRACE_KEY,
            {"trace-id": "123", "parent-id": "321", "sampling-priority": "1"},
            XraySubsegment.NAMESPACE,
        )

    def test_with_extractor_function(self):
        def extractor_foo(event, context):
            foo = event.get("foo", {})
            lowercase_foo = {k.lower(): v for k, v in foo.items()}

            trace_id = lowercase_foo.get(TraceHeader.TRACE_ID)
            parent_id = lowercase_foo.get(TraceHeader.PARENT_ID)
            sampling_priority = lowercase_foo.get(TraceHeader.SAMPLING_PRIORITY)
            return trace_id, parent_id, sampling_priority

        lambda_ctx = get_mock_context()
        ctx, ctx_source = extract_dd_trace_context(
            {
                "foo": {
                    TraceHeader.TRACE_ID: "123",
                    TraceHeader.PARENT_ID: "321",
                    TraceHeader.SAMPLING_PRIORITY: "1",
                }
            },
            lambda_ctx,
            extractor=extractor_foo,
        )
        self.assertEquals(ctx_source, "event")
        self.assertDictEqual(
            ctx, {"trace-id": "123", "parent-id": "321", "sampling-priority": "1",},
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "123",
                TraceHeader.PARENT_ID: "65535",
                TraceHeader.SAMPLING_PRIORITY: "1",
            },
        )

    def test_graceful_fail_of_extractor_function(self):
        def extractor_raiser(event, context):
            raise Exception("kreator")

        lambda_ctx = get_mock_context()
        ctx, ctx_source = extract_dd_trace_context(
            {
                "foo": {
                    TraceHeader.TRACE_ID: "123",
                    TraceHeader.PARENT_ID: "321",
                    TraceHeader.SAMPLING_PRIORITY: "1",
                }
            },
            lambda_ctx,
            extractor=extractor_raiser,
        )
        self.assertEquals(ctx_source, "xray")
        self.assertDictEqual(
            ctx, {"trace-id": "4369", "parent-id": "65535", "sampling-priority": "2",},
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "4369",
                TraceHeader.PARENT_ID: "65535",
                TraceHeader.SAMPLING_PRIORITY: "2",
            },
        )

    def test_with_sqs_distributed_datadog_trace_data(self):
        lambda_ctx = get_mock_context()
        sqs_event = {
            "Records": [
                {
                    "messageId": "059f36b4-87a3-44ab-83d2-661975830a7d",
                    "receiptHandle": "AQEBwJnKyrHigUMZj6rYigCgxlaS3SLy0a...",
                    "body": "Test message.",
                    "attributes": {
                        "ApproximateReceiveCount": "1",
                        "SentTimestamp": "1545082649183",
                        "SenderId": "AIDAIENQZJOLO23YVJ4VO",
                        "ApproximateFirstReceiveTimestamp": "1545082649185",
                    },
                    "messageAttributes": {
                        "_datadog": {
                            "stringValue": json.dumps(
                                {
                                    TraceHeader.TRACE_ID: "123",
                                    TraceHeader.PARENT_ID: "321",
                                    TraceHeader.SAMPLING_PRIORITY: "1",
                                }
                            )
                        }
                    },
                    "md5OfBody": "e4e68fb7bd0e697a0ae8f1bb342846b3",
                    "eventSource": "aws:sqs",
                    "eventSourceARN": "arn:aws:sqs:us-east-2:123456789012:my-queue",
                    "awsRegion": "us-east-2",
                }
            ]
        }
        ctx, source = extract_dd_trace_context(sqs_event, lambda_ctx)
        self.assertEqual(source, "event")
        self.assertDictEqual(
            ctx, {"trace-id": "123", "parent-id": "321", "sampling-priority": "1",},
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "123",
                TraceHeader.PARENT_ID: "65535",
                TraceHeader.SAMPLING_PRIORITY: "1",
            },
        )
        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_xray_recorder.begin_subsegment.assert_called()
        self.mock_xray_recorder.end_subsegment.assert_called()
        self.mock_current_subsegment.put_metadata.assert_called_with(
            XraySubsegment.TRACE_KEY,
            {"trace-id": "123", "parent-id": "321", "sampling-priority": "1"},
            XraySubsegment.NAMESPACE,
        )

    def test_with_client_context_datadog_trace_data(self):
        lambda_ctx = get_mock_context(
            custom={
                "_datadog": {
                    TraceHeader.TRACE_ID: "666",
                    TraceHeader.PARENT_ID: "777",
                    TraceHeader.SAMPLING_PRIORITY: "1",
                }
            }
        )
        ctx, source = extract_dd_trace_context({}, lambda_ctx)
        self.assertEqual(source, "event")
        self.assertDictEqual(
            ctx, {"trace-id": "666", "parent-id": "777", "sampling-priority": "1",},
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "666",
                TraceHeader.PARENT_ID: "65535",
                TraceHeader.SAMPLING_PRIORITY: "1",
            },
        )
        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_xray_recorder.begin_subsegment.assert_called()
        self.mock_xray_recorder.end_subsegment.assert_called()
        self.mock_current_subsegment.put_metadata.assert_called_with(
            XraySubsegment.TRACE_KEY,
            {"trace-id": "666", "parent-id": "777", "sampling-priority": "1"},
            XraySubsegment.NAMESPACE,
        )

    def test_with_complete_datadog_trace_headers_with_mixed_casing(self):
        lambda_ctx = get_mock_context()
        extract_dd_trace_context(
            {
                "headers": {
                    "X-Datadog-Trace-Id": "123",
                    "X-Datadog-Parent-Id": "321",
                    "X-Datadog-Sampling-Priority": "1",
                }
            },
            lambda_ctx,
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "123",
                TraceHeader.PARENT_ID: "65535",
                TraceHeader.SAMPLING_PRIORITY: "1",
            },
        )

    def test_with_complete_datadog_trace_headers_with_trigger_tags(self):
        trigger_tags = {
            "function_trigger.event_source": "sqs",
            "function_trigger.event_source_arn": "arn:aws:sqs:us-east-1:123456789012:MyQueue",
        }
        create_dd_dummy_metadata_subsegment(
            trigger_tags, XraySubsegment.LAMBDA_FUNCTION_TAGS_KEY
        )
        self.mock_xray_recorder.begin_subsegment.assert_called()
        self.mock_xray_recorder.end_subsegment.assert_called()
        self.mock_current_subsegment.put_metadata.assert_has_calls(
            [
                call(
                    XraySubsegment.LAMBDA_FUNCTION_TAGS_KEY,
                    {
                        "function_trigger.event_source": "sqs",
                        "function_trigger.event_source_arn": "arn:aws:sqs:us-east-1:123456789012:MyQueue",
                    },
                    XraySubsegment.NAMESPACE,
                ),
            ]
        )


class TestXRayContextConversion(unittest.TestCase):
    def test_convert_xray_trace_id(self):
        self.assertEqual(
            _convert_xray_trace_id("00000000e1be46a994272793"), "7043144561403045779"
        )

        self.assertEqual(
            _convert_xray_trace_id("bd862e3fe1be46a994272793"), "7043144561403045779"
        )

        self.assertEqual(
            _convert_xray_trace_id("ffffffffffffffffffffffff"),
            "9223372036854775807",  # 0x7FFFFFFFFFFFFFFF
        )

    def test_convert_xray_entity_id(self):
        self.assertEqual(
            _convert_xray_entity_id("53995c3f42cd8ad8"), "6023947403358210776"
        )

        self.assertEqual(
            _convert_xray_entity_id("1000000000000000"), "1152921504606846976"
        )

        self.assertEqual(
            _convert_xray_entity_id("ffffffffffffffff"), "18446744073709551615"
        )

    def test_convert_xray_sampling(self):
        self.assertEqual(_convert_xray_sampling(True), str(SamplingPriority.USER_KEEP))

        self.assertEqual(
            _convert_xray_sampling(False), str(SamplingPriority.USER_REJECT)
        )


class TestLogsInjection(unittest.TestCase):
    def setUp(self):
        patcher = patch("datadog_lambda.tracing.get_dd_trace_context")
        self.mock_get_dd_trace_context = patcher.start()
        self.mock_get_dd_trace_context.return_value = {
            TraceHeader.TRACE_ID: "123",
            TraceHeader.PARENT_ID: "456",
        }
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.tracing.is_lambda_context")
        self.mock_is_lambda_context = patcher.start()
        self.mock_is_lambda_context.return_value = True
        self.addCleanup(patcher.stop)

    def test_set_correlation_ids(self):
        set_correlation_ids()
        trace_id, span_id = get_correlation_ids()
        self.assertEqual(trace_id, 123)
        self.assertEqual(span_id, 456)


class TestFunctionSpanTags(unittest.TestCase):
    def test_function(self):
        ctx = get_mock_context()
        span = create_function_execution_span(ctx, "", False, {"source": ""}, False, {})
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(span.get_tag("function_version"), "$LATEST")

    def test_function_with_version(self):
        function_version = "1"
        ctx = get_mock_context(
            invoked_function_arn=function_arn + ":" + function_version
        )
        span = create_function_execution_span(ctx, "", False, {"source": ""}, False, {})
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(span.get_tag("function_version"), function_version)

    def test_function_with_alias(self):
        function_alias = "alias"
        ctx = get_mock_context(invoked_function_arn=function_arn + ":" + function_alias)
        span = create_function_execution_span(ctx, "", False, {"source": ""}, False, {})
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(span.get_tag("function_version"), function_alias)

    def test_function_with_trigger_tags(self):
        ctx = get_mock_context()
        span = create_function_execution_span(
            ctx,
            "",
            False,
            {"source": ""},
            False,
            {"function_trigger.event_source": "cloudwatch-logs"},
        )
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(
            span.get_tag("function_trigger.event_source"), "cloudwatch-logs"
        )
