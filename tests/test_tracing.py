import unittest
import json
import os

from unittest.mock import MagicMock, Mock, patch, call

import ddtrace

from ddtrace import tracer
from ddtrace.context import Context

from datadog_lambda.constants import (
    SamplingPriority,
    TraceHeader,
    XraySubsegment,
)
from datadog_lambda.tracing import (
    _deterministic_md5_hash,
    create_inferred_span,
    extract_dd_trace_context,
    create_dd_dummy_metadata_subsegment,
    create_function_execution_span,
    get_dd_trace_context,
    mark_trace_as_error_for_5xx_responses,
    set_correlation_ids,
    set_dd_trace_py_root,
    _convert_xray_trace_id,
    _convert_xray_entity_id,
    _convert_xray_sampling,
    InferredSpanInfo,
    extract_context_from_eventbridge_event,
)
from datadog_lambda.trigger import EventTypes

function_arn = "arn:aws:lambda:us-west-1:123457598159:function:python-layer-test"

fake_xray_header_value = (
    "Root=1-5e272390-8c398be037738dc042009320;Parent=94ae789b969f1cc5;Sampled=1"
)
fake_xray_header_value_parent_decimal = "10713633173203262661"
fake_xray_header_value_root_decimal = "3995693151288333088"

event_samples = "tests/event_samples/"

span_to_finish = None


def _clean_up_span():
    global span_to_finish
    if span_to_finish is not None:
        span_to_finish.finish()
        span_to_finish = None


def register_span(span):
    global span_to_finish
    _clean_up_span()
    span_to_finish = span
    return span


def wrapped_span_creator(span_creator_func):
    def result_func(*args, **kwargs):
        return register_span(span_creator_func(*args, **kwargs))

    return result_func


create_inferred_span = wrapped_span_creator(create_inferred_span)


class ClientContext(object):
    def __init__(self, custom=None):
        self.custom = custom


def get_mock_context(
    aws_request_id="request-id-1",
    memory_limit_in_mb="256",
    invoked_function_arn=function_arn,
    function_version="1",
    function_name="Function",
    custom=None,
):
    lambda_context = MagicMock()
    lambda_context.aws_request_id = aws_request_id
    lambda_context.memory_limit_in_mb = memory_limit_in_mb
    lambda_context.invoked_function_arn = invoked_function_arn
    lambda_context.function_version = function_version
    lambda_context.function_name = function_name
    lambda_context.client_context = ClientContext(custom)
    return lambda_context


class TestExtractAndGetDDTraceContext(unittest.TestCase):
    def setUp(self):
        global dd_tracing_enabled
        dd_tracing_enabled = False
        os.environ["_X_AMZN_TRACE_ID"] = fake_xray_header_value
        patcher = patch("datadog_lambda.tracing.send_segment")
        self.mock_send_segment = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch("datadog_lambda.tracing.is_lambda_context")
        self.mock_is_lambda_context = patcher.start()
        self.mock_is_lambda_context.return_value = True
        self.addCleanup(patcher.stop)

    def tearDown(self):
        global dd_tracing_enabled
        dd_tracing_enabled = False
        del os.environ["_X_AMZN_TRACE_ID"]

    def test_without_datadog_trace_headers(self):
        lambda_ctx = get_mock_context()
        ctx, source, event_source = extract_dd_trace_context({}, lambda_ctx)
        self.assertEqual(source, "xray")
        self.assertDictEqual(
            ctx,
            {
                "trace-id": fake_xray_header_value_root_decimal,
                "parent-id": fake_xray_header_value_parent_decimal,
                "sampling-priority": "2",
            },
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: fake_xray_header_value_root_decimal,
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
                TraceHeader.SAMPLING_PRIORITY: "2",
            },
            {},
        )

    def test_with_non_object_event(self):
        lambda_ctx = get_mock_context()
        ctx, source, event_source = extract_dd_trace_context(b"", lambda_ctx)
        self.assertEqual(source, "xray")
        self.assertDictEqual(
            ctx,
            {
                "trace-id": fake_xray_header_value_root_decimal,
                "parent-id": fake_xray_header_value_parent_decimal,
                "sampling-priority": "2",
            },
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: fake_xray_header_value_root_decimal,
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
                TraceHeader.SAMPLING_PRIORITY: "2",
            },
            {},
        )

    def test_with_incomplete_datadog_trace_headers(self):
        lambda_ctx = get_mock_context()
        ctx, source, event_source = extract_dd_trace_context(
            {"headers": {TraceHeader.TRACE_ID: "123", TraceHeader.PARENT_ID: "321"}},
            lambda_ctx,
        )
        self.assertEqual(source, "xray")
        self.assertDictEqual(
            ctx,
            {
                "trace-id": fake_xray_header_value_root_decimal,
                "parent-id": fake_xray_header_value_parent_decimal,
                "sampling-priority": "2",
            },
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: fake_xray_header_value_root_decimal,
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
                TraceHeader.SAMPLING_PRIORITY: "2",
            },
        )

    def test_with_complete_datadog_trace_headers(self):
        lambda_ctx = get_mock_context()
        ctx, source, event_source = extract_dd_trace_context(
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
            ctx,
            {"trace-id": "123", "parent-id": "321", "sampling-priority": "1"},
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "123",
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
                TraceHeader.SAMPLING_PRIORITY: "1",
            },
        )
        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_send_segment.assert_called()
        self.mock_send_segment.assert_called_with(
            XraySubsegment.TRACE_KEY,
            {"trace-id": "123", "parent-id": "321", "sampling-priority": "1"},
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
        ctx, ctx_source, event_source = extract_dd_trace_context(
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
        self.assertEqual(ctx_source, "event")
        self.assertDictEqual(
            ctx,
            {
                "trace-id": "123",
                "parent-id": "321",
                "sampling-priority": "1",
            },
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "123",
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
                TraceHeader.SAMPLING_PRIORITY: "1",
            },
        )

    def test_graceful_fail_of_extractor_function(self):
        def extractor_raiser(event, context):
            raise Exception("kreator")

        lambda_ctx = get_mock_context()
        ctx, ctx_source, event_source = extract_dd_trace_context(
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
        self.assertEqual(ctx_source, "xray")
        self.assertDictEqual(
            ctx,
            {
                "trace-id": fake_xray_header_value_root_decimal,
                "parent-id": fake_xray_header_value_parent_decimal,
                "sampling-priority": "2",
            },
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: fake_xray_header_value_root_decimal,
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
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
                            ),
                            "dataType": "String",
                        }
                    },
                    "md5OfBody": "e4e68fb7bd0e697a0ae8f1bb342846b3",
                    "eventSource": "aws:sqs",
                    "eventSourceARN": "arn:aws:sqs:us-east-2:123456789012:my-queue",
                    "awsRegion": "us-east-2",
                }
            ]
        }
        ctx, source, event_source = extract_dd_trace_context(sqs_event, lambda_ctx)
        self.assertEqual(source, "event")
        self.assertDictEqual(
            ctx,
            {
                "trace-id": "123",
                "parent-id": "321",
                "sampling-priority": "1",
            },
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "123",
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
                TraceHeader.SAMPLING_PRIORITY: "1",
            },
        )
        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_send_segment.assert_called_with(
            XraySubsegment.TRACE_KEY,
            {"trace-id": "123", "parent-id": "321", "sampling-priority": "1"},
        )

    def test_with_legacy_client_context_datadog_trace_data(self):
        lambda_ctx = get_mock_context(
            custom={
                "_datadog": {
                    TraceHeader.TRACE_ID: "666",
                    TraceHeader.PARENT_ID: "777",
                    TraceHeader.SAMPLING_PRIORITY: "1",
                }
            }
        )
        ctx, source, event_source = extract_dd_trace_context({}, lambda_ctx)
        self.assertEqual(source, "event")
        self.assertDictEqual(
            ctx,
            {
                "trace-id": "666",
                "parent-id": "777",
                "sampling-priority": "1",
            },
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "666",
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
                TraceHeader.SAMPLING_PRIORITY: "1",
            },
        )
        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_send_segment.assert_called()
        self.mock_send_segment.assert_called_with(
            XraySubsegment.TRACE_KEY,
            {"trace-id": "666", "parent-id": "777", "sampling-priority": "1"},
        )

    def test_with_new_client_context_datadog_trace_data(self):
        lambda_ctx = get_mock_context(
            custom={
                TraceHeader.TRACE_ID: "666",
                TraceHeader.PARENT_ID: "777",
                TraceHeader.SAMPLING_PRIORITY: "1",
            }
        )
        ctx, source, event_source = extract_dd_trace_context({}, lambda_ctx)
        self.assertEqual(source, "event")
        self.assertDictEqual(
            ctx,
            {
                "trace-id": "666",
                "parent-id": "777",
                "sampling-priority": "1",
            },
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "666",
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
                TraceHeader.SAMPLING_PRIORITY: "1",
            },
        )
        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_send_segment.assert_called()
        self.mock_send_segment.assert_called_with(
            XraySubsegment.TRACE_KEY,
            {"trace-id": "666", "parent-id": "777", "sampling-priority": "1"},
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
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
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
        self.mock_send_segment.assert_called()
        self.mock_send_segment.assert_has_calls(
            [
                call(
                    XraySubsegment.LAMBDA_FUNCTION_TAGS_KEY,
                    {
                        "function_trigger.event_source": "sqs",
                        "function_trigger.event_source_arn": "arn:aws:sqs:us-east-1:123456789012:MyQueue",
                    },
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
        span = tracer.current_span()
        self.assertEqual(span.trace_id, 123)
        self.assertEqual(span.span_id, 456)
        span.finish()

    def test_set_correlation_ids_handle_empty_trace_context(self):
        # neither x-ray or ddtrace is used. no tracing context at all.
        self.mock_get_dd_trace_context.return_value = {}
        # no exception thrown
        set_correlation_ids()
        span = tracer.current_span()
        self.assertIsNone(span)


class TestFunctionSpanTags(unittest.TestCase):
    def test_function(self):
        ctx = get_mock_context()
        span = create_function_execution_span(ctx, "", False, {"source": ""}, False, {})
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(span.get_tag("function_version"), "$LATEST")
        self.assertEqual(span.get_tag("resource_names"), "Function")
        self.assertEqual(span.get_tag("functionname"), "function")

    def test_function_with_version(self):
        function_version = "1"
        ctx = get_mock_context(
            invoked_function_arn=function_arn + ":" + function_version
        )
        span = create_function_execution_span(ctx, "", False, {"source": ""}, False, {})
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(span.get_tag("function_version"), function_version)
        self.assertEqual(span.get_tag("resource_names"), "Function")
        self.assertEqual(span.get_tag("functionname"), "function")

    def test_function_with_alias(self):
        function_alias = "alias"
        ctx = get_mock_context(invoked_function_arn=function_arn + ":" + function_alias)
        span = create_function_execution_span(ctx, "", False, {"source": ""}, False, {})
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(span.get_tag("function_version"), function_alias)
        self.assertEqual(span.get_tag("resource_names"), "Function")
        self.assertEqual(span.get_tag("functionname"), "function")

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
        self.assertEqual(span.get_tag("resource_names"), "Function")
        self.assertEqual(span.get_tag("functionname"), "function")
        self.assertEqual(
            span.get_tag("function_trigger.event_source"), "cloudwatch-logs"
        )


class TestSetTraceRootSpan(unittest.TestCase):
    def setUp(self):
        global dd_tracing_enabled
        dd_tracing_enabled = False
        os.environ["_X_AMZN_TRACE_ID"] = fake_xray_header_value
        patcher = patch("datadog_lambda.tracing.send_segment")
        self.mock_send_segment = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch("datadog_lambda.tracing.is_lambda_context")
        self.mock_is_lambda_context = patcher.start()
        self.mock_is_lambda_context.return_value = True
        self.addCleanup(patcher.stop)
        patcher = patch("ddtrace.tracer.context_provider.activate")
        self.mock_activate = patcher.start()
        self.mock_activate.return_value = True
        self.addCleanup(patcher.stop)

    def tearDown(self):
        global dd_tracing_enabled
        dd_tracing_enabled = False
        del os.environ["_X_AMZN_TRACE_ID"]

    def test_mixed_parent_context_when_merging(self):
        # When trace merging is enabled, and dd_trace headers are present,
        # use the dd-trace trace-id and the x-ray parent-id
        # This allows parenting relationships like dd-trace -> x-ray -> dd-trace
        lambda_ctx = get_mock_context()
        ctx, source, event_type = extract_dd_trace_context(
            {
                "headers": {
                    TraceHeader.TRACE_ID: "123",
                    TraceHeader.PARENT_ID: "321",
                    TraceHeader.SAMPLING_PRIORITY: "1",
                }
            },
            lambda_ctx,
        )
        set_dd_trace_py_root(
            source, True
        )  # When merging is off, always use dd-trace-context

        expected_context = Context(
            trace_id=123,  # Trace Id from incomming context
            span_id=int(fake_xray_header_value_parent_decimal),  # Parent Id from x-ray
            sampling_priority=1,  # Sampling priority from incomming context
        )
        self.mock_activate.assert_called()
        self.mock_activate.assert_has_calls([call(expected_context)])


class TestAuthorizerInferredSpans(unittest.TestCase):
    def setUp(self):
        patcher = patch("ddtrace.Span.finish", autospec=True)
        self.mock_span_stop = patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        _clean_up_span()

    def test_create_inferred_span_from_authorizer_request_api_gateway_v1_event(self):
        event_sample_source = "authorizer-request-api-gateway-v1"
        finish_time = (
            1663295021.832  # request_time_epoch + integrationLatency for api-gateway-v1
        )
        span = self._authorizer_span_testing_items(event_sample_source, finish_time)
        self._basic_common_checks(span, "aws.apigateway.rest")

    def test_create_inferred_span_from_authorizer_request_api_gateway_v1_cached_event(
        self,
    ):
        event_sample_source = "authorizer-request-api-gateway-v1-cached"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "abc123"  # injected data's requestId is abc321
        span = create_inferred_span(event, ctx)
        self.mock_span_stop.assert_not_called()  # NO authorizer span is injected
        self._basic_common_checks(span, "aws.apigateway.rest")

    def test_create_inferred_span_from_authorizer_token_api_gateway_v1_event(self):
        event_sample_source = "authorizer-token-api-gateway-v1"
        finish_time = (
            1663295021.832  # request_time_epoch + integrationLatency for api-gateway-v1
        )
        span = self._authorizer_span_testing_items(event_sample_source, finish_time)
        self._basic_common_checks(span, "aws.apigateway.rest")

    def test_create_inferred_span_from_authorizer_token_api_gateway_v2_cached_event(
        self,
    ):
        event_sample_source = "authorizer-token-api-gateway-v1-cached"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "abc123"  # injected data's requestId is abc321
        span = create_inferred_span(event, ctx)
        self.mock_span_stop.assert_not_called()  # NO authorizer span is injected
        self._basic_common_checks(span, "aws.apigateway.rest")

    def test_create_inferred_span_from_authorizer_request_api_gateway_v2_event(self):
        event_sample_source = "authorizer-request-api-gateway-v2"
        finish_time = 1664228639533775400  # use the injected parent span finish time as an approximation
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "abc123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "sync")
        self.mock_span_stop.assert_not_called()
        self.assertEqual(span.start_ns, finish_time)
        self._basic_common_checks(span, "aws.httpapi")

    def test_create_inferred_span_from_authorizer_request_api_gateway_v2_cached_event(
        self,
    ):
        event_sample_source = "authorizer-request-api-gateway-v2-cached"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "abc123"  # injected data's requestId is abc321
        span = create_inferred_span(event, ctx)
        self.mock_span_stop.assert_not_called()  # NO authorizer span is injected
        self._basic_common_checks(span, "aws.httpapi")

    def test_create_inferred_span_from_authorizer_request_api_gateway_websocket_connect_event(
        self,
    ):
        event_sample_source = "authorizer-request-api-gateway-websocket-connect"
        finish_time = (
            1664388386.892  # request_time_epoch + integrationLatency in websocket case
        )
        span = self._authorizer_span_testing_items(event_sample_source, finish_time)
        self._basic_common_checks(
            span, "aws.apigateway.websocket", "web", "$connect", None
        )

    def test_create_inferred_span_from_authorizer_request_api_gateway_websocket_message_event(
        self,
    ):
        event_sample_source = "authorizer-request-api-gateway-websocket-message"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "abc123"  # injected data's requestId is abc321
        span = create_inferred_span(event, ctx)
        self.mock_span_stop.assert_not_called()  # NO authorizer span is injected
        self._basic_common_checks(span, "aws.apigateway.websocket", "web", "main", None)

    def _authorizer_span_testing_items(self, event_sample_source, finish_time):
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "abc123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "sync")

        # checking the upstream_authorizer_span
        self.mock_span_stop.assert_called_once()
        args, kwargs = self.mock_span_stop.call_args_list[0]
        self.assertEqual(kwargs.get("finish_time", args[1]), finish_time)
        self.assertEqual(span.start, finish_time)
        authorizer_span = args[0]
        self.assertEqual(authorizer_span.name, "aws.apigateway.authorizer")
        self.assertEqual(span.parent_id, authorizer_span.span_id)
        return span

    def _basic_common_checks(
        self,
        span,
        operation_name,
        span_type="http",
        route_key="/hello",
        http_method="GET",
    ):
        self.assertEqual(span.get_tag("apiid"), "amddr1rix9")
        self.assertEqual(span.get_tag("apiname"), "amddr1rix9")
        self.assertEqual(span.get_tag("stage"), "dev")
        self.assertEqual(span.get_tag("operation_name"), operation_name)
        self.assertEqual(span.span_type, span_type)
        self.assertEqual(
            span.service,
            "amddr1rix9.execute-api.eu-west-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "amddr1rix9.execute-api.eu-west-1.amazonaws.com" + route_key,
        )
        self.assertEqual(span.get_tag("endpoint"), route_key)
        self.assertEqual(span.get_tag("http.method"), http_method)
        self.assertEqual(
            span.get_tag("resource_names"),
            f"{http_method} {route_key}" if http_method else route_key,
        )
        self.assertEqual(span.get_tag("request_id"), "abc123")


class TestInferredSpans(unittest.TestCase):
    def tearDown(self):
        _clean_up_span()

    def test_create_inferred_span_from_api_gateway_event(self):
        event_sample_source = "api-gateway"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.apigateway.rest")
        self.assertEqual(
            span.service,
            "70ixmpl4fl.execute-api.us-east-2.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "70ixmpl4fl.execute-api.us-east-2.amazonaws.com/path/to/resource",
        )
        self.assertEqual(span.get_tag("endpoint"), "/path/to/resource")
        self.assertEqual(span.get_tag("http.method"), "POST")
        self.assertEqual(
            span.get_tag("resource_names"),
            "POST /path/to/resource",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("apiid"), "1234567890")
        self.assertEqual(span.get_tag("apiname"), "1234567890")
        self.assertEqual(span.get_tag("stage"), "prod")
        self.assertEqual(span.start, 1428582896.0)
        self.assertEqual(span.span_type, "http")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "sync")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_api_gateway_non_proxy_event_async(self):
        event_sample_source = "api-gateway-non-proxy-async"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.apigateway.rest")
        self.assertEqual(
            span.service,
            "lgxbo6a518.execute-api.eu-west-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "lgxbo6a518.execute-api.eu-west-1.amazonaws.com/http/get",
        )
        self.assertEqual(span.get_tag("endpoint"), "/http/get")
        self.assertEqual(span.get_tag("http.method"), "GET")
        self.assertEqual(
            span.get_tag("resource_names"),
            "GET /http/get",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("apiid"), "lgxbo6a518")
        self.assertEqual(span.get_tag("apiname"), "lgxbo6a518")
        self.assertEqual(span.get_tag("stage"), "dev")
        self.assertEqual(span.start, 1631210915.2510002)
        self.assertEqual(span.span_type, "http")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "async")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_api_gateway_non_proxy_event_sync(self):
        event_sample_source = "api-gateway-non-proxy"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.apigateway.rest")
        self.assertEqual(
            span.service,
            "lgxbo6a518.execute-api.eu-west-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "lgxbo6a518.execute-api.eu-west-1.amazonaws.com/http/get",
        )
        self.assertEqual(span.get_tag("endpoint"), "/http/get")
        self.assertEqual(span.get_tag("http.method"), "GET")
        self.assertEqual(
            span.get_tag("resource_names"),
            "GET /http/get",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("apiid"), "lgxbo6a518")
        self.assertEqual(span.get_tag("apiname"), "lgxbo6a518")
        self.assertEqual(span.get_tag("stage"), "dev")
        self.assertEqual(span.start, 1631210915.2510002)
        self.assertEqual(span.span_type, "http")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "sync")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_http_api_event(self):
        event_sample_source = "http-api"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.httpapi")
        self.assertEqual(
            span.service,
            "x02yirxc7a.execute-api.eu-west-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "x02yirxc7a.execute-api.eu-west-1.amazonaws.com/httpapi/get",
        )
        self.assertEqual(span.get_tag("endpoint"), "/httpapi/get")
        self.assertEqual(span.get_tag("http.method"), "GET")
        self.assertEqual(
            span.get_tag("resource_names"),
            "GET /httpapi/get",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("apiid"), "x02yirxc7a")
        self.assertEqual(span.get_tag("apiname"), "x02yirxc7a")
        self.assertEqual(span.get_tag("stage"), "$default")
        self.assertEqual(span.get_tag("http.protocol"), "HTTP/1.1")
        self.assertEqual(span.get_tag("http.source_ip"), "38.122.226.210")
        self.assertEqual(span.get_tag("http.user_agent"), "curl/7.64.1")
        self.assertEqual(span.start, 1631212283.738)
        self.assertEqual(span.span_type, "http")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "sync")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_api_gateway_websocket_default_event(self):
        event_sample_source = "api-gateway-websocket-default"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.apigateway.websocket")
        self.assertEqual(
            span.service,
            "p62c47itsb.execute-api.eu-west-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "p62c47itsb.execute-api.eu-west-1.amazonaws.com$default",
        )
        self.assertEqual(span.get_tag("endpoint"), "$default")
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "$default",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("apiid"), "p62c47itsb")
        self.assertEqual(span.get_tag("apiname"), "p62c47itsb")
        self.assertEqual(span.get_tag("stage"), "dev")
        self.assertEqual(span.get_tag("connection_id"), "Fc5SzcoYGjQCJlg=")
        self.assertEqual(span.get_tag("event_type"), "MESSAGE")
        self.assertEqual(span.get_tag("message_direction"), "IN")
        self.assertEqual(span.start, 1631285061.365)
        self.assertEqual(span.span_type, "web")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "sync")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_api_gateway_websocket_connect_event(self):
        event_sample_source = "api-gateway-websocket-connect"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.apigateway.websocket")
        self.assertEqual(
            span.service,
            "p62c47itsb.execute-api.eu-west-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "p62c47itsb.execute-api.eu-west-1.amazonaws.com$connect",
        )
        self.assertEqual(span.get_tag("endpoint"), "$connect")
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "$connect",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("apiid"), "p62c47itsb")
        self.assertEqual(span.get_tag("apiname"), "p62c47itsb")
        self.assertEqual(span.get_tag("stage"), "dev")
        self.assertEqual(span.get_tag("connection_id"), "Fc2tgfl3mjQCJfA=")
        self.assertEqual(span.get_tag("event_type"), "CONNECT")
        self.assertEqual(span.get_tag("message_direction"), "IN")
        self.assertEqual(span.start, 1631284003.071)
        self.assertEqual(span.span_type, "web")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "sync")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_api_gateway_websocket_disconnect_event(self):
        event_sample_source = "api-gateway-websocket-disconnect"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.apigateway.websocket")
        self.assertEqual(
            span.service,
            "p62c47itsb.execute-api.eu-west-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "p62c47itsb.execute-api.eu-west-1.amazonaws.com$disconnect",
        )
        self.assertEqual(span.get_tag("endpoint"), "$disconnect")
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "$disconnect",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("apiid"), "p62c47itsb")
        self.assertEqual(span.get_tag("apiname"), "p62c47itsb")
        self.assertEqual(span.get_tag("stage"), "dev")
        self.assertEqual(span.get_tag("connection_id"), "Fc2tgfl3mjQCJfA=")
        self.assertEqual(span.get_tag("event_type"), "DISCONNECT")
        self.assertEqual(span.get_tag("message_direction"), "IN")
        self.assertEqual(span.start, 1631284034.737)
        self.assertEqual(span.span_type, "web")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "sync")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_sqs_event_string_msg_attr(self):
        event_sample_name = "sqs-string-msg-attribute"
        test_file = event_samples + event_sample_name + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.sqs")
        self.assertEqual(
            span.service,
            "sqs",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            None,
        )
        self.assertEqual(span.get_tag("endpoint"), None)
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "InferredSpansQueueNode",
        )
        self.assertEqual(span.get_tag("request_id"), None)
        self.assertEqual(span.get_tag("queuename"), "InferredSpansQueueNode")
        self.assertEqual(
            span.get_tag("event_source_arn"),
            "arn:aws:sqs:eu-west-1:601427279990:InferredSpansQueueNode",
        )
        self.assertEqual(
            span.get_tag("sender_id"),
            "AROAYYB64AB3LSVUYFP5T:harv-inferred-spans-dev-initSender",
        )
        self.assertEqual(span.start, 1634662094.538)
        self.assertEqual(span.span_type, "web")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "async")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_sns_event_string_msg_attr(self):
        event_sample_name = "sns-string-msg-attribute"
        test_file = event_samples + event_sample_name + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.sns")
        self.assertEqual(
            span.service,
            "sns",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            None,
        )
        self.assertEqual(span.get_tag("endpoint"), None)
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "serverlessTracingTopicPy",
        )
        self.assertEqual(span.get_tag("topicname"), "serverlessTracingTopicPy")
        self.assertEqual(
            span.get_tag("topic_arn"),
            "arn:aws:sns:eu-west-1:601427279990:serverlessTracingTopicPy",
        )
        self.assertEqual(
            span.get_tag("message_id"), "87056a47-f506-5d77-908b-303605d3b197"
        )
        self.assertEqual(span.get_tag("type"), "Notification")
        self.assertEqual(span.get_tag("subject"), None)
        self.assertEqual(span.start, 1643638421.637)
        self.assertEqual(span.span_type, "web")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "async")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_sns_event_b64_msg_attr(self):
        event_sample_name = "sns-b64-msg-attribute"
        test_file = event_samples + event_sample_name + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.sns")
        self.assertEqual(
            span.service,
            "sns",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            None,
        )
        self.assertEqual(span.get_tag("endpoint"), None)
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "serverlessTracingTopicPy",
        )
        self.assertEqual(span.get_tag("topicname"), "serverlessTracingTopicPy")
        self.assertEqual(
            span.get_tag("topic_arn"),
            "arn:aws:sns:eu-west-1:601427279990:serverlessTracingTopicPy",
        )
        self.assertEqual(
            span.get_tag("message_id"), "87056a47-f506-5d77-908b-303605d3b197"
        )
        self.assertEqual(span.get_tag("type"), "Notification")
        self.assertEqual(span.get_tag("subject"), None)
        self.assertEqual(span.start, 1643638421.637)
        self.assertEqual(span.span_type, "web")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "async")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_kinesis_event(self):
        event_sample_source = "kinesis"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.kinesis")
        self.assertEqual(
            span.service,
            "kinesis",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            None,
        )
        self.assertEqual(span.get_tag("endpoint"), None)
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "stream/kinesisStream",
        )
        self.assertEqual(span.get_tag("request_id"), None)
        self.assertEqual(span.get_tag("streamname"), "stream/kinesisStream")
        self.assertEqual(span.get_tag("shardid"), "shardId-000000000002")
        self.assertEqual(
            span.get_tag("event_source_arn"),
            "arn:aws:kinesis:eu-west-1:601427279990:stream/kinesisStream",
        )
        self.assertEqual(
            span.get_tag("event_id"),
            "shardId-000000000002:49624230154685806402418173680709770494154422022871973922",
        )
        self.assertEqual(span.get_tag("event_name"), "aws:kinesis:record")
        self.assertEqual(span.get_tag("event_version"), "1.0")
        self.assertEqual(span.get_tag("partition_key"), "partitionkey")
        self.assertEqual(span.start, 1643638425.163)
        self.assertEqual(span.span_type, "web")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "async")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_dynamodb_event(self):
        event_sample_source = "dynamodb"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.dynamodb")
        self.assertEqual(
            span.service,
            "dynamodb",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            None,
        )
        self.assertEqual(span.get_tag("endpoint"), None)
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "ExampleTableWithStream",
        )
        self.assertEqual(span.get_tag("request_id"), None)
        self.assertEqual(span.get_tag("tablename"), "ExampleTableWithStream")
        self.assertEqual(
            span.get_tag("event_source_arn"),
            "arn:aws:dynamodb:us-east-1:123456789012:table/ExampleTableWithStream/stream/2015-06-27T00:48:05.899",
        )
        self.assertEqual(span.get_tag("event_id"), "c4ca4238a0b923820dcc509a6f75849b")
        self.assertEqual(span.get_tag("event_name"), "INSERT")
        self.assertEqual(span.get_tag("event_version"), "1.1")
        self.assertEqual(span.get_tag("stream_view_type"), "NEW_AND_OLD_IMAGES")
        self.assertEqual(span.get_tag("size_bytes"), "26")
        self.assertEqual(span.start, 1428537600.0)
        self.assertEqual(span.span_type, "web")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "async")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_s3_event(self):
        event_sample_source = "s3"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.s3")
        self.assertEqual(
            span.service,
            "s3",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            None,
        )
        self.assertEqual(span.get_tag("endpoint"), None)
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "example-bucket",
        )
        self.assertEqual(span.get_tag("request_id"), None)
        self.assertEqual(span.get_tag("event_name"), "ObjectCreated:Put")
        self.assertEqual(span.get_tag("bucketname"), "example-bucket")
        self.assertEqual(span.get_tag("bucket_arn"), "arn:aws:s3:::example-bucket")
        self.assertEqual(span.get_tag("object_key"), "test/key")
        self.assertEqual(span.get_tag("object_size"), "1024")
        self.assertEqual(
            span.get_tag("object_etag"), "0123456789abcdef0123456789abcdef"
        )
        self.assertEqual(span.start, 0.0)
        self.assertEqual(span.span_type, "web")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "async")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_create_inferred_span_from_eventbridge_event(self):
        event_sample_source = "eventbridge-custom"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.eventbridge")
        self.assertEqual(
            span.service,
            "eventbridge",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            None,
        )
        self.assertEqual(span.get_tag("endpoint"), None)
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "eventbridge.custom.event.sender",
        )
        self.assertEqual(span.get_tag("request_id"), None)
        self.assertEqual(span.start, 1635989865.0)
        self.assertEqual(span.span_type, "web")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "async")
        self.assertEqual(span.get_tag("peer.service"), "function")

    def test_extract_context_from_eventbridge_event(self):
        event_sample_source = "eventbridge-custom"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        trace, parent, sampling = extract_context_from_eventbridge_event(event, ctx)
        self.assertEqual(trace, "12345")
        self.assertEqual(parent, "67890"),
        self.assertEqual(sampling, "2")

    def test_extract_dd_trace_context_for_eventbridge(self):
        event_sample_source = "eventbridge-custom"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        context, source, event_type = extract_dd_trace_context(event, ctx)
        self.assertEqual(context["trace-id"], "12345")
        self.assertEqual(context["parent-id"], "67890")

    def test_extract_context_from_sqs_event_with_string_msg_attr(self):
        event_sample_source = "sqs-string-msg-attribute"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        context, source, event_type = extract_dd_trace_context(event, ctx)
        self.assertEqual(context["trace-id"], "2684756524522091840")
        self.assertEqual(context["parent-id"], "7431398482019833808")
        self.assertEqual(context["sampling-priority"], "1")

    def test_extract_context_from_sqs_batch_event(self):
        event_sample_source = "sqs-batch"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        context, source, event_source = extract_dd_trace_context(event, ctx)
        self.assertEqual(context["trace-id"], "2684756524522091840")
        self.assertEqual(context["parent-id"], "7431398482019833808")
        self.assertEqual(context["sampling-priority"], "1")

    def test_extract_context_from_sns_event_with_string_msg_attr(self):
        event_sample_source = "sns-string-msg-attribute"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        context, source, event_source = extract_dd_trace_context(event, ctx)
        self.assertEqual(context["trace-id"], "4948377316357291421")
        self.assertEqual(context["parent-id"], "6746998015037429512")
        self.assertEqual(context["sampling-priority"], "1")

    def test_extract_context_from_sns_event_with_b64_msg_attr(self):
        event_sample_source = "sns-b64-msg-attribute"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        context, source, event_source = extract_dd_trace_context(event, ctx)
        self.assertEqual(context["trace-id"], "4948377316357291421")
        self.assertEqual(context["parent-id"], "6746998015037429512")
        self.assertEqual(context["sampling-priority"], "1")

    def test_extract_context_from_sns_batch_event(self):
        event_sample_source = "sns-batch"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        context, source, event_source = extract_dd_trace_context(event, ctx)
        self.assertEqual(context["trace-id"], "4948377316357291421")
        self.assertEqual(context["parent-id"], "6746998015037429512")
        self.assertEqual(context["sampling-priority"], "1")

    def test_extract_context_from_kinesis_event(self):
        event_sample_source = "kinesis"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        context, source, event_source = extract_dd_trace_context(event, ctx)
        self.assertEqual(context["trace-id"], "4948377316357291421")
        self.assertEqual(context["parent-id"], "2876253380018681026")
        self.assertEqual(context["sampling-priority"], "1")

    def test_extract_context_from_kinesis_batch_event(self):
        event_sample_source = "kinesis-batch"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        context, source, event_source = extract_dd_trace_context(event, ctx)
        self.assertEqual(context["trace-id"], "4948377316357291421")
        self.assertEqual(context["parent-id"], "2876253380018681026")
        self.assertEqual(context["sampling-priority"], "1")

    def test_create_inferred_span_from_api_gateway_event_no_apiid(self):
        event_sample_source = "api-gateway-no-apiid"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.apigateway.rest")
        self.assertEqual(
            span.service,
            "70ixmpl4fl.execute-api.us-east-2.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "70ixmpl4fl.execute-api.us-east-2.amazonaws.com/path/to/resource",
        )
        self.assertEqual(span.get_tag("endpoint"), "/path/to/resource")
        self.assertEqual(span.get_tag("http.method"), "POST")
        self.assertEqual(
            span.get_tag("resource_names"),
            "POST /path/to/resource",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("apiid"), "None")
        self.assertEqual(span.get_tag("apiname"), "None")
        self.assertEqual(span.get_tag("stage"), "prod")
        self.assertEqual(span.start, 1428582896.0)
        self.assertEqual(span.span_type, "http")
        self.assertEqual(span.get_tag(InferredSpanInfo.TAG_SOURCE), "self")
        self.assertEqual(span.get_tag(InferredSpanInfo.SYNCHRONICITY), "sync")

    @patch("datadog_lambda.tracing.submit_errors_metric")
    def test_mark_trace_as_error_for_5xx_responses_getting_400_response_code(
        self, mock_submit_errors_metric
    ):
        mark_trace_as_error_for_5xx_responses(
            context="fake_context", status_code="400", span="empty_span"
        )
        mock_submit_errors_metric.assert_not_called()

    @patch("datadog_lambda.tracing.submit_errors_metric")
    def test_mark_trace_as_error_for_5xx_responses_sends_error_metric_and_set_error_tags(
        self, mock_submit_errors_metric
    ):
        mock_span = Mock(ddtrace.span.Span)
        status_code = "500"
        mark_trace_as_error_for_5xx_responses(
            context="fake_context", status_code=status_code, span=mock_span
        )
        mock_submit_errors_metric.assert_called_once()
        self.assertEqual(1, mock_span.error)

    def test_no_error_with_nonetype_headers(self):
        lambda_ctx = get_mock_context()
        ctx, source, event_type = extract_dd_trace_context(
            {"headers": None},
            lambda_ctx,
        )
        self.assertEqual(ctx, None)


class TestStepFunctionsTraceContext(unittest.TestCase):
    def test_deterministic_m5_hash(self):
        result = _deterministic_md5_hash("some_testing_random_string")
        self.assertEqual("2251275791555400689", result)

    def test_deterministic_m5_hash__result_the_same_as_backend(self):
        result = _deterministic_md5_hash(
            "arn:aws:states:sa-east-1:601427271234:express:DatadogStateMachine:acaf1a67-336a-e854-1599-2a627eb2dd8a"
            ":c8baf081-31f1-464d-971f-70cb17d01111#step-one#2022-12-08T21:08:19.224Z"
        )
        self.assertEqual("8034507082463708833", result)

    def test_deterministic_m5_hash__always_leading_with_zero(self):
        for i in range(100):
            result = _deterministic_md5_hash(str(i))
            result_in_binary = bin(int(result))
            # Leading zeros will be omitted, so only test for full 64 bits present
            if len(result_in_binary) == 66:  # "0b" + 64 bits.
                self.assertTrue(result_in_binary.startswith("0b0"))
