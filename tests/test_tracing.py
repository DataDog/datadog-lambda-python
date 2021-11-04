import unittest
import json
import os

from unittest.mock import MagicMock, patch, call

from ddtrace.helpers import get_correlation_ids
from ddtrace.context import Context

from datadog_lambda.constants import SamplingPriority, TraceHeader, XraySubsegment
from datadog_lambda.tracing import (
    create_inferred_span,
    extract_dd_trace_context,
    create_dd_dummy_metadata_subsegment,
    create_function_execution_span,
    get_dd_trace_context,
    set_correlation_ids,
    set_dd_trace_py_root,
    _convert_xray_trace_id,
    _convert_xray_entity_id,
    _convert_xray_sampling,
)

function_arn = "arn:aws:lambda:us-west-1:123457598159:function:python-layer-test"

fake_xray_header_value = (
    "Root=1-5e272390-8c398be037738dc042009320;Parent=94ae789b969f1cc5;Sampled=1"
)
fake_xray_header_value_parent_decimal = "10713633173203262661"
fake_xray_header_value_root_decimal = "3995693151288333088"

event_samples = "tests/event_samples/"


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
        ctx, source = extract_dd_trace_context({}, lambda_ctx)
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
        ctx, source = extract_dd_trace_context(
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
        ctx, source = extract_dd_trace_context({}, lambda_ctx)
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
        ctx, source = extract_dd_trace_context({}, lambda_ctx)
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
        trace_id, span_id = get_correlation_ids()
        self.assertEqual(trace_id, 123)
        self.assertEqual(span_id, 456)


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


class TestInferredSpans(unittest.TestCase):
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
            span.get_tag("service.name"),
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
            "70ixmpl4fl.execute-api.us-east-2.amazonaws.com/path/to/resource",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("span_type"), "inferred")
        self.assertEqual(span.start, 1428582896.0)
        self.assertEqual(span.span_type, "http")

    def test_create_inferred_span_from_api_gateway_non_proxy_event(self):
        event_sample_source = "api-gateway-non-proxy"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.apigateway.rest")
        self.assertEqual(
            span.get_tag("service.name"),
            "lgxbo6a518.execute-api.sa-east-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "lgxbo6a518.execute-api.sa-east-1.amazonaws.com/http/get",
        )
        self.assertEqual(span.get_tag("endpoint"), "/http/get")
        self.assertEqual(span.get_tag("http.method"), "GET")
        self.assertEqual(
            span.get_tag("resource_names"),
            "lgxbo6a518.execute-api.sa-east-1.amazonaws.com/http/get",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("span_type"), "inferred")
        self.assertEqual(span.start, 1631210915.2509997)
        self.assertEqual(span.span_type, "http")

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
            span.get_tag("service.name"),
            "x02yirxc7a.execute-api.sa-east-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "x02yirxc7a.execute-api.sa-east-1.amazonaws.com/httpapi/get",
        )
        self.assertEqual(span.get_tag("endpoint"), "/httpapi/get")
        self.assertEqual(span.get_tag("http.method"), "GET")
        self.assertEqual(
            span.get_tag("resource_names"),
            "x02yirxc7a.execute-api.sa-east-1.amazonaws.com/httpapi/get",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("span_type"), "inferred")
        self.assertEqual(span.start, 1631212283.738)
        self.assertEqual(span.span_type, "http")

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
            span.get_tag("service.name"),
            "p62c47itsb.execute-api.sa-east-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "p62c47itsb.execute-api.sa-east-1.amazonaws.com$default",
        )
        self.assertEqual(span.get_tag("endpoint"), "$default")
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "p62c47itsb.execute-api.sa-east-1.amazonaws.com$default",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("span_type"), "inferred")
        self.assertEqual(span.start, 1631285061.365)
        self.assertEqual(span.span_type, "web")

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
            span.get_tag("service.name"),
            "p62c47itsb.execute-api.sa-east-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "p62c47itsb.execute-api.sa-east-1.amazonaws.com$connect",
        )
        self.assertEqual(span.get_tag("endpoint"), "$connect")
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "p62c47itsb.execute-api.sa-east-1.amazonaws.com$connect",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("span_type"), "inferred")
        self.assertEqual(span.start, 1631284003.071)
        self.assertEqual(span.span_type, "web")

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
            span.get_tag("service.name"),
            "p62c47itsb.execute-api.sa-east-1.amazonaws.com",
        )
        self.assertEqual(
            span.get_tag("http.url"),
            "p62c47itsb.execute-api.sa-east-1.amazonaws.com$disconnect",
        )
        self.assertEqual(span.get_tag("endpoint"), "$disconnect")
        self.assertEqual(span.get_tag("http.method"), None)
        self.assertEqual(
            span.get_tag("resource_names"),
            "p62c47itsb.execute-api.sa-east-1.amazonaws.com$disconnect",
        )
        self.assertEqual(span.get_tag("request_id"), "123")
        self.assertEqual(span.get_tag("span_type"), "inferred")
        self.assertEqual(span.start, 1631284034.737)
        self.assertEqual(span.span_type, "web")

    def test_create_inferred_span_from_sqs_event(self):
        event_sample_source = "sqs"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.sqs")
        self.assertEqual(
            span.get_tag("service.name"),
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
            "MyQueue",
        )
        self.assertEqual(span.get_tag("request_id"), None)
        self.assertEqual(span.get_tag("span_type"), "inferred")
        self.assertEqual(span.start, 1523232000.0)
        self.assertEqual(span.span_type, "web")

    def test_create_inferred_span_from_sns_event(self):
        event_sample_source = "sns"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            event = json.load(event)
        ctx = get_mock_context()
        ctx.aws_request_id = "123"
        span = create_inferred_span(event, ctx)
        self.assertEqual(span.get_tag("operation_name"), "aws.sns")
        self.assertEqual(
            span.get_tag("service.name"),
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
            "ExampleTopic",
        )
        self.assertEqual(span.get_tag("request_id"), None)
        self.assertEqual(span.get_tag("span_type"), "inferred")
        # TODO FIXME: investigate why this is flaky
        # self.assertEqual(span.start, 18000.0)
        self.assertEqual(span.span_type, "web")

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
            span.get_tag("service.name"),
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
            "EXAMPLE",
        )
        self.assertEqual(span.get_tag("request_id"), None)
        self.assertEqual(span.get_tag("span_type"), "inferred")
        self.assertEqual(span.start, 1428537600.0)
        self.assertEqual(span.span_type, "web")

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
            span.get_tag("service.name"),
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
        self.assertEqual(span.get_tag("span_type"), "inferred")
        self.assertEqual(span.start, 1428537600.0)
        self.assertEqual(span.span_type, "web")

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
            span.get_tag("service.name"),
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
        self.assertEqual(span.get_tag("span_type"), "inferred")
        self.assertEqual(span.start, 18000.0)
        self.assertEqual(span.span_type, "web")
