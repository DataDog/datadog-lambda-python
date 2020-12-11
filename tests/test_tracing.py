import unittest

try:
    from unittest.mock import MagicMock, patch, call
except ImportError:
    from mock import MagicMock, patch, call

from ddtrace.helpers import get_correlation_ids

from datadog_lambda.constants import SamplingPriority, TraceHeader, XraySubsegment
from datadog_lambda.tracing import (
    extract_dd_trace_context,
    create_dd_metadata_subsegment,
    create_function_execution_span,
    get_dd_trace_context,
    set_correlation_ids,
    _convert_xray_trace_id,
    _convert_xray_entity_id,
    _convert_xray_sampling,
)

function_arn = "arn:aws:lambda:us-west-1:123457598159:function:python-layer-test"


def get_mock_context(
    aws_request_id="request-id-1",
    memory_limit_in_mb="256",
    invoked_function_arn=function_arn,
    function_version="1",
):
    lambda_context = MagicMock()
    lambda_context.aws_request_id = aws_request_id
    lambda_context.memory_limit_in_mb = memory_limit_in_mb
    lambda_context.invoked_function_arn = invoked_function_arn
    lambda_context.function_version = function_version
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
        ctx, source = extract_dd_trace_context({})
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

    def test_with_incomplete_datadog_trace_headers(self):
        ctx, source = extract_dd_trace_context(
            {"headers": {TraceHeader.TRACE_ID: "123", TraceHeader.PARENT_ID: "321"}}
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
        event = {
            "headers": {
                TraceHeader.TRACE_ID: "123",
                TraceHeader.PARENT_ID: "321",
                TraceHeader.SAMPLING_PRIORITY: "1",
            }
        }
        ctx, source = extract_dd_trace_context(event)
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
        create_dd_metadata_subsegment(event, ctx, {})
        self.mock_xray_recorder.begin_subsegment.assert_called()
        self.mock_xray_recorder.end_subsegment.assert_called()
        self.mock_current_subsegment.put_metadata.assert_called_with(
            XraySubsegment.TRACE_KEY,
            {"trace-id": "123", "parent-id": "321", "sampling-priority": "1"},
            XraySubsegment.NAMESPACE,
        )

    def test_with_complete_datadog_trace_headers_with_mixed_casing(self):
        extract_dd_trace_context(
            {
                "headers": {
                    "X-Datadog-Trace-Id": "123",
                    "X-Datadog-Parent-Id": "321",
                    "X-Datadog-Sampling-Priority": "1",
                }
            },
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
        event = {
            "headers": {
                TraceHeader.TRACE_ID: "123",
                TraceHeader.PARENT_ID: "321",
                TraceHeader.SAMPLING_PRIORITY: "1",
            }
        }
        trigger_tags = {
            "trigger.event_source": "sqs",
            "trigger.event_source_arn": "arn:aws:sqs:us-east-1:123456789012:MyQueue",
        }
        ctx, source = extract_dd_trace_context(event)
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
        create_dd_metadata_subsegment(event, ctx, trigger_tags)
        self.mock_xray_recorder.begin_subsegment.assert_called()
        self.mock_xray_recorder.end_subsegment.assert_called()
        self.mock_current_subsegment.put_metadata.assert_has_calls(
            [
                call(
                    XraySubsegment.TRACE_KEY,
                    {"trace-id": "123", "parent-id": "321", "sampling-priority": "1"},
                    XraySubsegment.NAMESPACE,
                ),
                call(
                    XraySubsegment.ROOT_SPAN_METADATA_KEY,
                    {
                        "trigger.event_source": "sqs",
                        "trigger.event_source_arn": "arn:aws:sqs:us-east-1:123456789012:MyQueue",
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
        self.assertEqual(trace_id, "123")
        self.assertEqual(span_id, "456")


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
            {"trigger.event_source": "cloudwatch-logs"},
        )
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(span.get_tag("trigger.event_source"), "cloudwatch-logs")
