import base64
import copy
import functools
import json
import traceback
import pytest
import os
import unittest

from unittest.mock import Mock, patch, call, ANY

import ddtrace

from ddtrace.trace import Context, tracer
from ddtrace._trace._span_pointer import _SpanPointer
from ddtrace._trace._span_pointer import _SpanPointerDirection
from ddtrace._trace._span_pointer import _SpanPointerDescription

from datadog_lambda.constants import (
    SamplingPriority,
    TraceHeader,
    TraceContextSource,
    XraySubsegment,
)
from datadog_lambda.tracing import (
    HIGHER_64_BITS,
    LOWER_64_BITS,
    _deterministic_sha256_hash,
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
    create_service_mapping,
    determine_service_name,
    service_mapping as global_service_mapping,
    propagator,
    emit_telemetry_on_exception_outside_of_handler,
    _dsm_set_checkpoint,
    extract_context_from_kinesis_event,
    extract_context_from_sqs_or_sns_event_or_context,
)

from datadog_lambda.trigger import parse_event_source
from tests.utils import get_mock_context, ClientContext


function_arn = "arn:aws:lambda:us-west-1:123457598159:function:python-layer-test"

fake_xray_header_value = (
    "Root=1-5e272390-8c398be037738dc042009320;Parent=94ae789b969f1cc5;Sampled=1"
)
fake_xray_header_value_parent_decimal = "10713633173203262661"
fake_xray_header_value_root_decimal = "3995693151288333088"

event_samples = "tests/event_samples/"


def with_trace_propagation_style(style):
    style_list = list(style.split(","))

    def _wrapper(fn):
        @functools.wraps(fn)
        def _wrap(*args, **kwargs):
            from ddtrace.propagation.http import config

            orig_extract = config._propagation_style_extract
            orig_inject = config._propagation_style_inject
            config._propagation_style_extract = style_list
            config._propagation_style_inject = style_list
            try:
                return fn(*args, **kwargs)
            finally:
                config._propagation_style_extract = orig_extract
                config._propagation_style_inject = orig_inject

        return _wrap

    return _wrapper


_test_extract_dd_trace_context = (
    ("api-gateway", Context(trace_id=12345, span_id=67890, sampling_priority=2)),
    (
        "api-gateway-no-apiid",
        Context(trace_id=12345, span_id=67890, sampling_priority=2),
    ),
    (
        "api-gateway-non-proxy",
        Context(trace_id=12345, span_id=67890, sampling_priority=2),
    ),
    (
        "api-gateway-non-proxy-async",
        Context(trace_id=12345, span_id=67890, sampling_priority=2),
    ),
    (
        "api-gateway-websocket-connect",
        Context(trace_id=12345, span_id=67890, sampling_priority=2),
    ),
    (
        "api-gateway-websocket-default",
        Context(trace_id=12345, span_id=67890, sampling_priority=2),
    ),
    (
        "api-gateway-websocket-disconnect",
        Context(trace_id=12345, span_id=67890, sampling_priority=2),
    ),
    (
        "authorizer-request-api-gateway-v1",
        Context(
            trace_id=13478705995797221209,
            span_id=8471288263384216896,
            sampling_priority=1,
        ),
    ),
    ("authorizer-request-api-gateway-v1-cached", None),
    (
        "authorizer-request-api-gateway-v2",
        Context(
            trace_id=14356983619852933354,
            span_id=12658621083505413809,
            sampling_priority=1,
        ),
    ),
    ("authorizer-request-api-gateway-v2-cached", None),
    (
        "authorizer-request-api-gateway-websocket-connect",
        Context(
            trace_id=5351047404834723189,
            span_id=18230460631156161837,
            sampling_priority=1,
        ),
    ),
    ("authorizer-request-api-gateway-websocket-message", None),
    (
        "authorizer-token-api-gateway-v1",
        Context(
            trace_id=17874798268144902712,
            span_id=16184667399315372101,
            sampling_priority=1,
        ),
    ),
    ("authorizer-token-api-gateway-v1-cached", None),
    ("cloudfront", None),
    ("cloudwatch-events", None),
    ("cloudwatch-logs", None),
    ("custom", None),
    ("dynamodb", None),
    ("eventbridge-custom", Context(trace_id=12345, span_id=67890, sampling_priority=2)),
    (
        "eventbridge-sqs",
        Context(
            trace_id=7379586022458917877,
            span_id=2644033662113726488,
            sampling_priority=1,
        ),
    ),
    ("http-api", Context(trace_id=12345, span_id=67890, sampling_priority=2)),
    (
        "kinesis",
        Context(
            trace_id=4948377316357291421,
            span_id=2876253380018681026,
            sampling_priority=1,
        ),
    ),
    (
        "kinesis-batch",
        Context(
            trace_id=4948377316357291421,
            span_id=2876253380018681026,
            sampling_priority=1,
        ),
    ),
    ("lambda-url", None),
    (
        "rum-appsync",
        Context(
            trace_id=12345,
            span_id=67890,
            sampling_priority=1,
        ),
    ),
    ("rum-appsync-no-headers", None),
    ("rum-appsync-request-not-dict", None),
    ("s3", None),
    (
        "sns-b64-msg-attribute",
        Context(
            trace_id=4948377316357291421,
            span_id=6746998015037429512,
            sampling_priority=1,
        ),
    ),
    (
        "sns-batch",
        Context(
            trace_id=4948377316357291421,
            span_id=6746998015037429512,
            sampling_priority=1,
        ),
    ),
    (
        "sns-string-msg-attribute",
        Context(
            trace_id=4948377316357291421,
            span_id=6746998015037429512,
            sampling_priority=1,
        ),
    ),
    (
        "sqs-batch",
        Context(
            trace_id=2684756524522091840,
            span_id=7431398482019833808,
            sampling_priority=1,
        ),
    ),
    (
        "sqs-java-upstream",
        Context(
            trace_id=7925498337868555493,
            span_id=5245570649555658903,
            sampling_priority=1,
        ),
    ),
    (
        "sns-sqs-java-upstream",
        Context(
            trace_id=4781801699472307582,
            span_id=7752697518321801287,
            sampling_priority=1,
        ),
    ),
    (
        "sqs-string-msg-attribute",
        Context(
            trace_id=2684756524522091840,
            span_id=7431398482019833808,
            sampling_priority=1,
        ),
    ),
    ({"headers": None}, None),
)


@pytest.mark.parametrize("event,expect", _test_extract_dd_trace_context)
def test_extract_dd_trace_context(event, expect):
    if isinstance(event, str):
        with open(f"{event_samples}{event}.json") as f:
            event = json.load(f)
    ctx = get_mock_context()

    actual, _, _ = extract_dd_trace_context(event, ctx)
    assert (expect is None) is (actual is None)
    assert (expect is None) or actual.trace_id == expect.trace_id
    assert (expect is None) or actual.span_id == expect.span_id
    assert (expect is None) or actual.sampling_priority == expect.sampling_priority


class TestExtractAndGetDDTraceContext(unittest.TestCase):
    def setUp(self):
        os.environ["_X_AMZN_TRACE_ID"] = fake_xray_header_value
        patcher = patch("datadog_lambda.tracing.send_segment")
        self.mock_send_segment = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch("datadog_lambda.config.Config.is_lambda_context")
        self.mock_is_lambda_context = patcher.start()
        self.mock_is_lambda_context.return_value = True
        self.addCleanup(patcher.stop)

    def tearDown(self):
        del os.environ["_X_AMZN_TRACE_ID"]

    @with_trace_propagation_style("datadog")
    def test_without_datadog_trace_headers(self):
        lambda_ctx = get_mock_context()
        ctx, source, event_source = extract_dd_trace_context({}, lambda_ctx)
        self.assertEqual(source, "xray")
        self.assertEqual(
            ctx,
            Context(
                trace_id=int(fake_xray_header_value_root_decimal),
                span_id=int(fake_xray_header_value_parent_decimal),
                sampling_priority=2,
            ),
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

    @with_trace_propagation_style("datadog")
    def test_with_non_object_event(self):
        lambda_ctx = get_mock_context()
        ctx, source, event_source = extract_dd_trace_context(b"", lambda_ctx)
        self.assertEqual(source, "xray")
        self.assertEqual(
            ctx,
            Context(
                trace_id=int(fake_xray_header_value_root_decimal),
                span_id=int(fake_xray_header_value_parent_decimal),
                sampling_priority=2,
            ),
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

    @with_trace_propagation_style("datadog")
    def test_with_incomplete_datadog_trace_headers(self):
        lambda_ctx = get_mock_context()
        ctx, source, event_source = extract_dd_trace_context(
            {"headers": {TraceHeader.TRACE_ID: "123"}},
            lambda_ctx,
        )
        self.assertEqual(source, "xray")
        self.assertEqual(
            ctx,
            Context(
                trace_id=int(fake_xray_header_value_root_decimal),
                span_id=int(fake_xray_header_value_parent_decimal),
                sampling_priority=2,
            ),
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: fake_xray_header_value_root_decimal,
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
                TraceHeader.SAMPLING_PRIORITY: "2",
            },
        )

    def common_tests_with_trace_context_extraction_injection(
        self, headers, event_containing_headers, lambda_context=get_mock_context()
    ):
        ctx, source, event_source = extract_dd_trace_context(
            event_containing_headers,
            lambda_context,
        )
        self.assertEqual(source, "event")
        expected_context = propagator.extract(headers)
        self.assertEqual(ctx, expected_context)
        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_send_segment.assert_called()
        self.mock_send_segment.assert_called_with(
            XraySubsegment.TRACE_KEY,
            expected_context,
        )
        # when no active ddtrace context, xray context would be used
        expected_context.span_id = int(fake_xray_header_value_parent_decimal)
        expected_headers = {}
        propagator.inject(expected_context, expected_headers)
        dd_context_headers = get_dd_trace_context()
        self.assertDictEqual(expected_headers, dd_context_headers)

    @with_trace_propagation_style("datadog")
    def test_with_complete_datadog_trace_headers(self):
        headers = {
            TraceHeader.TRACE_ID: "123",
            TraceHeader.PARENT_ID: "321",
            TraceHeader.SAMPLING_PRIORITY: "1",
        }
        self.common_tests_with_trace_context_extraction_injection(
            headers, {"headers": headers}
        )

    @with_trace_propagation_style("tracecontext")
    def test_with_w3c_trace_headers(self):
        headers = {
            "traceparent": "00-0000000000000000000000000000007b-0000000000000141-01",
            "tracestate": "dd=s:2;t.dm:-0,rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
        }
        self.common_tests_with_trace_context_extraction_injection(
            headers, {"headers": headers}
        )

    @with_trace_propagation_style("datadog")
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
        self.assertEqual(
            ctx,
            Context(
                trace_id=123,
                span_id=321,
                sampling_priority=1,
            ),
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "123",
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
                TraceHeader.SAMPLING_PRIORITY: "1",
            },
        )

    @with_trace_propagation_style("datadog")
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
        self.assertEqual(
            ctx,
            Context(
                trace_id=int(fake_xray_header_value_root_decimal),
                span_id=int(fake_xray_header_value_parent_decimal),
                sampling_priority=2,
            ),
        )
        self.assertDictEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: fake_xray_header_value_root_decimal,
                TraceHeader.PARENT_ID: fake_xray_header_value_parent_decimal,
                TraceHeader.SAMPLING_PRIORITY: "2",
            },
        )

    @with_trace_propagation_style("datadog")
    def test_with_sqs_distributed_datadog_trace_data(self):
        headers = {
            TraceHeader.TRACE_ID: "123",
            TraceHeader.PARENT_ID: "321",
            TraceHeader.SAMPLING_PRIORITY: "1",
        }
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
                            "stringValue": json.dumps(headers),
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
        self.common_tests_with_trace_context_extraction_injection(headers, sqs_event)

    @with_trace_propagation_style("tracecontext")
    def test_with_sqs_distributed_w3c_trace_data(self):
        headers = {
            "traceparent": "00-0000000000000000000000000000007b-0000000000000141-01",
            "tracestate": "dd=s:2;t.dm:-0,rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
        }
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
                            "stringValue": json.dumps(headers),
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
        self.common_tests_with_trace_context_extraction_injection(headers, sqs_event)

    @with_trace_propagation_style("datadog")
    def test_with_legacy_client_context_datadog_trace_data(self):
        headers = {
            TraceHeader.TRACE_ID: "666",
            TraceHeader.PARENT_ID: "777",
            TraceHeader.SAMPLING_PRIORITY: "1",
        }
        lambda_ctx = get_mock_context(custom={"_datadog": headers})
        self.common_tests_with_trace_context_extraction_injection(
            headers, {}, lambda_ctx
        )

    @with_trace_propagation_style("tracecontext")
    def test_with_legacy_client_context_w3c_trace_data(self):
        headers = {
            "traceparent": "00-0000000000000000000000000000029a-0000000000000309-01",
            "tracestate": "dd=s:1;t.dm:-0,rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
        }
        lambda_ctx = get_mock_context(custom={"_datadog": headers})
        self.common_tests_with_trace_context_extraction_injection(
            headers, {}, lambda_ctx
        )

    @with_trace_propagation_style("datadog")
    def test_with_new_client_context_datadog_trace_data(self):
        headers = {
            TraceHeader.TRACE_ID: "666",
            TraceHeader.PARENT_ID: "777",
            TraceHeader.SAMPLING_PRIORITY: "1",
        }
        lambda_ctx = get_mock_context(custom=headers)
        self.common_tests_with_trace_context_extraction_injection(
            headers, {}, lambda_ctx
        )

    @with_trace_propagation_style("tracecontext")
    def test_with_new_client_context_w3c_trace_data(self):
        headers = {
            "traceparent": "00-0000000000000000000000000000029a-0000000000000309-01",
            "tracestate": "dd=s:1;t.dm:-0,rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
        }
        lambda_ctx = get_mock_context(custom=headers)
        self.common_tests_with_trace_context_extraction_injection(
            headers, {}, lambda_ctx
        )

    @with_trace_propagation_style("datadog")
    def test_with_complete_datadog_trace_headers_with_mixed_casing(self):
        lambda_ctx = get_mock_context()
        headers = {
            "X-Datadog-Trace-Id": "123",
            "X-Datadog-Parent-Id": "321",
            "X-Datadog-Sampling-Priority": "1",
        }
        extract_dd_trace_context(
            {"headers": headers},
            lambda_ctx,
        )
        extract_headers = {}
        context = propagator.extract(headers)
        context.span_id = fake_xray_header_value_parent_decimal
        propagator.inject(context, extract_headers)
        self.assertDictEqual(extract_headers, get_dd_trace_context())

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

    def test_request_header_malformed(self):
        """Testing that if a RUM AppSync event is malformed, the tracer will attempt
        to get the trace context from the lambda context in the
        extract_context_from_request_header_or_context function."""
        lambda_ctx = get_mock_context()
        lambda_ctx.client_context = ClientContext(
            custom={
                "_datadog": {
                    "x-datadog-parent-id": "67890",
                    "x-datadog-sampling-priority": "1",
                    "x-datadog-trace-id": "12345",
                }
            }
        )
        request_header_event = {
            "identity": "None",
            "info": {
                "fieldName": "getItems",
                "parentTypeName": "Query",
                "selectionSetGraphQL": "{\n  id\n}",
                "selectionSetList": ["id"],
            },
            "prev": "None",
            "request": "hello",
            "source": "None",
        }
        ctx, source, _ = extract_dd_trace_context(request_header_event, lambda_ctx)
        expected_context = Context(
            trace_id=12345,
            span_id=67890,
            sampling_priority=1,
        )

        self.assertEqual(ctx, expected_context)
        self.assertEqual(source, "event")

    def _test_step_function_trace_data_common(
        self, event, expected_trace_id, expected_span_id, expected_tid
    ):
        """Common test logic for step function trace data tests"""
        lambda_ctx = get_mock_context()
        expected_context = Context(
            trace_id=expected_trace_id,
            span_id=expected_span_id,
            sampling_priority=1,
            meta={"_dd.p.tid": expected_tid},
        )
        expected_headers = {
            TraceHeader.TRACE_ID: str(expected_trace_id),
            TraceHeader.PARENT_ID: "10713633173203262661",
            TraceHeader.SAMPLING_PRIORITY: "1",
            TraceHeader.TAGS: f"_dd.p.tid={expected_tid}",
        }

        ctx, source, _ = extract_dd_trace_context(event, lambda_ctx)

        self.assertEqual(source, "event")
        self.assertEqual(ctx, expected_context)
        self.assertEqual(get_dd_trace_context(), expected_headers)

        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_send_segment.assert_called_with(
            XraySubsegment.TRACE_KEY,
            expected_context,
        )

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data(self):
        """Test basic step function trace data extraction"""
        sfn_event = {
            "Execution": {
                "Id": "arn:aws:states:sa-east-1:425362996713:execution:abhinav-activity-state-machine:72a7ca3e-901c-41bb-b5a3-5f279b92a316",
                "Name": "72a7ca3e-901c-41bb-b5a3-5f279b92a316",
                "RoleArn": "arn:aws:iam::425362996713:role/service-role/StepFunctions-abhinav-activity-state-machine-role-22jpbgl6j",
                "StartTime": "2024-12-04T19:38:04.069Z",
                "RedriveCount": 0,
            },
            "State": {
                "Name": "Lambda Invoke",
                "EnteredTime": "2024-12-04T19:38:04.118Z",
                "RetryCount": 0,
            },
            "StateMachine": {
                "Id": "arn:aws:states:sa-east-1:425362996713:stateMachine:abhinav-activity-state-machine",
                "Name": "abhinav-activity-state-machine",
            },
        }
        self._test_step_function_trace_data_common(
            sfn_event, 435175499815315247, 3929055471293792800, "3e7a89d1b7310603"
        )

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data_retry(self):
        """Test step function trace data extraction with non-zero retry count"""
        sfn_event = {
            "Execution": {
                "Id": "arn:aws:states:sa-east-1:425362996713:execution:abhinav-activity-state-machine:72a7ca3e-901c-41bb-b5a3-5f279b92a316",
                "Name": "72a7ca3e-901c-41bb-b5a3-5f279b92a316",
                "RoleArn": "arn:aws:iam::425362996713:role/service-role/StepFunctions-abhinav-activity-state-machine-role-22jpbgl6j",
                "StartTime": "2024-12-04T19:38:04.069Z",
                "RedriveCount": 0,
            },
            "State": {
                "Name": "Lambda Invoke",
                "EnteredTime": "2024-12-04T19:38:04.118Z",
                "RetryCount": 1,
            },
            "StateMachine": {
                "Id": "arn:aws:states:sa-east-1:425362996713:stateMachine:abhinav-activity-state-machine",
                "Name": "abhinav-activity-state-machine",
            },
        }
        self._test_step_function_trace_data_common(
            sfn_event, 435175499815315247, 5063839446130725204, "3e7a89d1b7310603"
        )

    # https://github.com/DataDog/logs-backend/blob/65ea567150f24e5498008f3cf8cabef9ea995f5d/domains/serverless/apps/logs-to-traces-reducer/src/test/resources/test-json-files/stepfunctions/RedriveTest/snapshots/RedriveLambdaSuccessTraceMerging.json#L45-L46
    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data_redrive(self):
        """Test step function trace data extraction with non-zero redrive count"""
        sfn_event = {
            "Execution": {
                "Id": "arn:aws:states:sa-east-1:425362996713:execution:abhinav-activity-state-machine:72a7ca3e-901c-41bb-b5a3-5f279b92a316",
                "Name": "72a7ca3e-901c-41bb-b5a3-5f279b92a316",
                "RoleArn": "arn:aws:iam::425362996713:role/service-role/StepFunctions-abhinav-activity-state-machine-role-22jpbgl6j",
                "StartTime": "2024-12-04T19:38:04.069Z",
                "RedriveCount": 1,
            },
            "State": {
                "Name": "Lambda Invoke",
                "EnteredTime": "2024-12-04T19:38:04.118Z",
                "RetryCount": 0,
            },
            "StateMachine": {
                "Id": "arn:aws:states:sa-east-1:425362996713:stateMachine:abhinav-activity-state-machine",
                "Name": "abhinav-activity-state-machine",
            },
        }
        self._test_step_function_trace_data_common(
            sfn_event, 435175499815315247, 8782364156266188026, "3e7a89d1b7310603"
        )

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data_lambda_root(self):
        """Test JSONata style step function trace data extraction where there's an upstream Lambda"""
        sfn_event = {
            "_datadog": {
                "Execution": {
                    "Id": "665c417c-1237-4742-aaca-8b3becbb9e75",
                    "RedriveCount": 0,
                },
                "StateMachine": {},
                "State": {
                    "Name": "my-awesome-state",
                    "EnteredTime": "Mon Nov 13 12:43:33 PST 2023",
                    "RetryCount": 0,
                },
                "x-datadog-trace-id": "5821803790426892636",
                "x-datadog-tags": "_dd.p.dm=-0,_dd.p.tid=672a7cb100000000",
                "serverless-version": "v1",
            }
        }
        self._test_step_function_trace_data_common(
            sfn_event, 5821803790426892636, 6880978411788117524, "672a7cb100000000"
        )

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data_sfn_root(self):
        """Test JSONata style step function trace data extraction where there's an upstream step function"""
        sfn_event = {
            "_datadog": {
                "Execution": {
                    "Id": "665c417c-1237-4742-aaca-8b3becbb9e75",
                    "RedriveCount": 0,
                },
                "StateMachine": {},
                "State": {
                    "Name": "my-awesome-state",
                    "EnteredTime": "Mon Nov 13 12:43:33 PST 2023",
                    "RetryCount": 0,
                },
                "RootExecutionId": "4875aba4-ae31-4a4c-bf8a-63e9eee31dad",
                "serverless-version": "v1",
            }
        }
        self._test_step_function_trace_data_common(
            sfn_event, 4521899030418994483, 6880978411788117524, "12d1270d99cc5e03"
        )

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data_eventbridge(self):
        """Test step function trace data extraction through EventBridge"""
        eventbridge_event = {
            "version": "0",
            "id": "eaacd8db-02de-ab13-ed5a-8ffb84048294",
            "detail-type": "StepFunctionTask",
            "source": "my.eventbridge",
            "account": "425362996713",
            "time": "2025-03-13T15:17:34Z",
            "region": "sa-east-1",
            "resources": [
                "arn:aws:states:sa-east-1:425362996713:stateMachine:abhinav-inner-state-machine",
                "arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:912eaa4c-291a-488a-bda3-d06bcc21203d",
            ],
            "detail": {
                "Message": "Hello from Step Functions!",
                "TaskToken": "AQCEAAAAKgAAAAMAAAAAAAAAAeMHr6sb8Ll5IKntjIiLGaBkaNeweo84kKYKDTvDaSAP1vjuYRJEGqFdHsKMyZL8ZcgAdanKpkbhPEN5hpoCe+BH9KblWeDsJxkDCk/meN5SaPlC1qS7Q/7/KqBq+tmAOCSy+MjdqFsnihy5Yo6g6C9uuPn7ccSB/609d8pznFm9nigEos/82emwi18lm67/+/bn4RTX4S7qV4RoGWUWUPeHfr34xWOipCt4SVDkoQPZdRVpq3wyRJP2zcK0zup24/opJqKKSCI5Q9orALNB2jEjDyQ9LE4mSrafoe0tcm/bOAGfrcpR3AwtArUiF6JPYd7Nw0XWWyPXFBjiQTJDhZFlGfllJ1N91eiN8wlzUX1+I0vw/t2PoEmuQ2VCJYCbl1ybjX/tQ97GZ9ogjY9N7VYy5uD5xfZ6VAyetUR06HUtbUIXTVxULm7wmsHb979W/fIQXsrxbFzc0+ypKaqGXJBoq7xX//irjpuNhWg1Wgfn0hxuXl5oN/LkqI83T8f9SdnJMxRDpaHDpttqbjVESB/Pf9o7gakjJj12+r2uiJNc81k50uhuHdFOGsImFHKV8hb1LGcq0ZzUKT5SbEDV2k+ezOP+O9Sk4c0unbpNLM3PKLKxVLhu2gtiIIVCHUHGmumW",
                "_datadog": {
                    "Execution": {
                        "Id": "arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:912eaa4c-291a-488a-bda3-d06bcc21203d",
                        "StartTime": "2025-03-13T15:17:33.972Z",
                        "Name": "912eaa4c-291a-488a-bda3-d06bcc21203d",
                        "RoleArn": "arn:aws:iam::425362996713:role/service-role/StepFunctions-abhinav-activity-state-machine-role-22jpbgl6j",
                        "RedriveCount": 0,
                    },
                    "StateMachine": {
                        "Id": "arn:aws:states:sa-east-1:425362996713:stateMachine:abhinav-inner-state-machine",
                        "Name": "abhinav-inner-state-machine",
                    },
                    "State": {
                        "Name": "EventBridge PutEvents",
                        "EnteredTime": "2025-03-13T15:17:34.008Z",
                        "RetryCount": 0,
                    },
                    "Task": {
                        "Token": "AQCEAAAAKgAAAAMAAAAAAAAAAeMHr6sb8Ll5IKntjIiLGaBkaNeweo84kKYKDTvDaSAP1vjuYRJEGqFdHsKMyZL8ZcgAdanKpkbhPEN5hpoCe+BH9KblWeDsJxkDCk/meN5SaPlC1qS7Q/7/KqBq+tmAOCSy+MjdqFsnihy5Yo6g6C9uuPn7ccSB/609d8pznFm9nigEos/82emwi18lm67/+/bn4RTX4S7qV4RoGWUWUPeHfr34xWOipCt4SVDkoQPZdRVpq3wyRJP2zcK0zup24/opJqKKSCI5Q9orALNB2jEjDyQ9LE4mSrafoe0tcm/bOAGfrcpR3AwtArUiF6JPYd7Nw0XWWyPXFBjiQTJDhZFlGfllJ1N91eiN8wlzUX1+I0vw/t2PoEmuQ2VCJYCbl1ybjX/tQ97GZ9ogjY9N7VYy5uD5xfZ6VAyetUR06HUtbUIXTVxULm7wmsHb979W/fIQXsrxbFzc0+ypKaqGXJBoq7xX//irjpuNhWg1Wgfn0hxuXl5oN/LkqI83T8f9SdnJMxRDpaHDpttqbjVESB/Pf9o7gakjJj12+r2uiJNc81k50uhuHdFOGsImFHKV8hb1LGcq0ZzUKT5SbEDV2k+ezOP+O9Sk4c0unbpNLM3PKLKxVLhu2gtiIIVCHUHGmumW"
                    },
                    "RootExecutionId": "arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:912eaa4c-291a-488a-bda3-d06bcc21203d",
                    "serverless-version": "v1",
                },
            },
        }
        self._test_step_function_trace_data_common(
            eventbridge_event,
            3401561763239692811,
            10430178702434539423,
            "a49ff3b7fb47b0b",
        )

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data_sqs(self):
        """Test step function trace data extraction through SQS"""
        sqs_event = {
            "Records": [
                {
                    "EventSource": "aws:sns",
                    "EventVersion": "1.0",
                    "EventSubscriptionArn": "arn:aws:sns:sa-east-1:425362996713:logs-to-traces-dev-topic:f1653ba3-2ff7-4c8e-9381-45a7a62f9708",
                    "Sns": {
                        "Type": "Notification",
                        "MessageId": "e39184ea-bfd8-5efa-96fe-e4a64a457ff7",
                        "TopicArn": "arn:aws:sns:sa-east-1:425362996713:logs-to-traces-dev-topic",
                        "Subject": None,
                        "Message": "{}",
                        "Timestamp": "2025-03-13T15:01:49.942Z",
                        "SignatureVersion": "1",
                        "Signature": "WJHKq+pNOLgxa7+dB1dud02RM/30Jvz+KiMZzjRl38/Pphz90H24eGyIbnq3BJXYEyawFCHC6sq/5HcwXouGc5gbah6he+JpqXahMEs6cyMs2tg9SXxooRHEGv5iiZXKhnDcJYOrQ+iFExO9w+WFWfJjO2m/EDVVSYvuDjDV7mmTwAgEOD0zUvWpT7wOeKGG5Uk916Ppy3iMV7sCoHV/RwVikdhCWDDmxbdqteGduAXPdGESE/aj6kUx9ibEOKXyhC+7H1/j0tlhUchl6LZsTf1Gaiq2yEqKXKvsupcG3hRZ6FtIWP0jGlFhpW5EHc2oiHIVOsQceCYPqXYMCZvFuA==",
                        "SigningCertUrl": "https://sns.sa-east-1.amazonaws.com/SimpleNotificationService-9c6465fa7f48f5cacd23014631ec1136.pem",
                        "UnsubscribeUrl": "https://sns.sa-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:sa-east-1:425362996713:logs-to-traces-dev-topic:f1653ba3-2ff7-4c8e-9381-45a7a62f9708",
                        "MessageAttributes": {
                            "_datadog": {
                                "Type": "String",
                                "Value": '{"Execution":{"Id":"arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:79478846-0cff-44de-91f5-02c96ff65762","StartTime":"2025-03-13T15:01:49.738Z","Name":"79478846-0cff-44de-91f5-02c96ff65762","RoleArn":"arn:aws:iam::425362996713:role/service-role/StepFunctions-abhinav-activity-state-machine-role-22jpbgl6j","RedriveCount":0},"StateMachine":{"Id":"arn:aws:states:sa-east-1:425362996713:stateMachine:abhinav-inner-state-machine","Name":"abhinav-inner-state-machine"},"State":{"Name":"SNS Publish","EnteredTime":"2025-03-13T15:01:49.768Z","RetryCount":0},"RootExecutionId":"arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:79478846-0cff-44de-91f5-02c96ff65762","serverless-version":"v1"}',
                            }
                        },
                    },
                }
            ]
        }
        self._test_step_function_trace_data_common(
            sqs_event, 3818106616964044169, 15912108710769293902, "3a4fd1a254eb514a"
        )

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data_eventbridge_sqs(self):
        """Test step function trace data extraction through EventBridge and SQS"""
        eventbridge_sqs_event = {
            "Records": [
                {
                    "messageId": "9ed082ad-2f4d-4309-ab99-9553d2be5613",
                    "receiptHandle": "AQEB6z7FatNIXbWOTC4Bx+udD0flrnT7XMehruTohl8O2KI2t9hvo5oxGIOhwcb+QtS5aRXsFE35TgGE8kZHlHK7Sa8jQUen6XmsPG7qB6BPdXjr0eunM2SDAtLj0mDSKx907VIKRYQG+qpI9ZyNK7Bi786oQIz2UkZGZru9zlXxJtAQiXBqfJ+OfTzhIwkPu04czU6lYfAbxdyNaBNdBEsTNJKPjquvcq1ZBVCHkn9L6wo8jha6XreoeS2WJ5N26ZLKtAl3wlSUByB92OKZU2mEuNboyY7bgK+nkx4N8fVVrafVXnY9YHuq60eQcZ/nusWFeJlVyN7NFypYP2IOn25xylltEACKbgUdEsFU2h5k7yI2DVk5eAt9vB6qmAJlgfkGsXG0SZrCADoIKXl9jpwajw==",
                    "body": '{"version":"0","id":"ff6d828b-b35e-abdf-64b6-6ea2cf698c0b","detail-type":"StepFunctionTask","source":"my.eventbridge","account":"425362996713","time":"2025-03-13T15:14:21Z","region":"sa-east-1","resources":["arn:aws:states:sa-east-1:425362996713:stateMachine:abhinav-inner-state-machine","arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:fe087266-fe48-4a31-a21b-691f4e7ea985"],"detail":{"Message":"Hello from Step Functions!","TaskToken":"AQCEAAAAKgAAAAMAAAAAAAAAAfi3HMLTw3u9h0vSmkjyHlK1tv5bQUyA7i+6LIvrBWu+3S+DMuQ79JpMtAuCaMN/AGSuGPO7OPeTNA/9v7/kzAsLoPzwPhbrDPXP4SVF1YIO663PvtX/tEWxnAfwLqwDyx8G8VEsVLcmiiOafFCKJwn0OP/DoAWc0sjhWwRxIoQ0ipBGhOqU8rO8SFZVvxUbkosNejnhT7B6314pC89JZLpXU7SxFe+XrgN+uRAvFxsH/+RwDf94xk5hhtukH7HzhJKWN2WCtUISd84pM/1V7ppDuJ3FHgJT22xQIbEGA9Q4o+pLLehzE2SHCdo7eWYQqN+7BanxBNMI6kBMaf5nuh9izAp38lsrmHJyO8NvXgWg+F9hoTZX4RpV9CCwvRFrCRcCeDq4/uJzbvB4AwwA2q2Llm0X8yH0pKvPZ2v7pl4nCWdnEgj920I8AmBCuozbKP7gJRnAqfx3MnOSkpZTeGnHkp0ly8EevwCT2zX/1GQnCAx02kBaDJgUMputFeruMBzwVtlEVBFUUgaWbJwHzz2htuAw282pdATrKfv4VV1N962uLBJ32wd9a92rX7VXXToitvZGIvf/Z7cu4xfAzxQH1rIQ3M4ojkR9r48qoYtnYDlEf+BkIL8L4+xpbRFSBk3p","_datadog":{"Execution":{"Id":"arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:fe087266-fe48-4a31-a21b-691f4e7ea985","StartTime":"2025-03-13T15:14:21.730Z","Name":"fe087266-fe48-4a31-a21b-691f4e7ea985","RoleArn":"arn:aws:iam::425362996713:role/service-role/StepFunctions-abhinav-activity-state-machine-role-22jpbgl6j","RedriveCount":0},"StateMachine":{"Id":"arn:aws:states:sa-east-1:425362996713:stateMachine:abhinav-inner-state-machine","Name":"abhinav-inner-state-machine"},"State":{"Name":"EventBridge PutEvents","EnteredTime":"2025-03-13T15:14:21.765Z","RetryCount":0},"Task":{"Token":"AQCEAAAAKgAAAAMAAAAAAAAAAfi3HMLTw3u9h0vSmkjyHlK1tv5bQUyA7i+6LIvrBWu+3S+DMuQ79JpMtAuCaMN/AGSuGPO7OPeTNA/9v7/kzAsLoPzwPhbrDPXP4SVF1YIO663PvtX/tEWxnAfwLqwDyx8G8VEsVLcmiiOafFCKJwn0OP/DoAWc0sjhWwRxIoQ0ipBGhOqU8rO8SFZVvxUbkosNejnhT7B6314pC89JZLpXU7SxFe+XrgN+uRAvFxsH/+RwDf94xk5hhtukH7HzhJKWN2WCtUISd84pM/1V7ppDuJ3FHgJT22xQIbEGA9Q4o+pLLehzE2SHCdo7eWYQqN+7BanxBNMI6kBMaf5nuh9izAp38lsrmHJyO8NvXgWg+F9hoTZX4RpV9CCwvRFrCRcCeDq4/uJzbvB4AwwA2q2Llm0X8yH0pKvPZ2v7pl4nCWdnEgj920I8AmBCuozbKP7gJRnAqfx3MnOSkpZTeGnHkp0ly8EevwCT2zX/1GQnCAx02kBaDJgUMputFeruMBzwVtlEVBFUUgaWbJwHzz2htuAw282pdATrKfv4VV1N962uLBJ32wd9a92rX7VXXToitvZGIvf/Z7cu4xfAzxQH1rIQ3M4ojkR9r48qoYtnYDlEf+BkIL8L4+xpbRFSBk3p"},"RootExecutionId":"arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:fe087266-fe48-4a31-a21b-691f4e7ea985","serverless-version":"v1"}}}',
                    "attributes": {
                        "ApproximateReceiveCount": "1",
                        "SentTimestamp": "1741878862068",
                        "SenderId": "AROAWGCM4HXUUNHLDXVER:6145b5ba998f311c8ac27f5cade2b915",
                        "ApproximateFirstReceiveTimestamp": "1741878862075",
                    },
                    "messageAttributes": {},
                    "md5OfBody": "e5cf8197b304a4dd4fd5db8e4842484b",
                    "eventSource": "aws:sqs",
                    "eventSourceARN": "arn:aws:sqs:sa-east-1:425362996713:abhinav-q",
                    "awsRegion": "sa-east-1",
                }
            ]
        }
        self._test_step_function_trace_data_common(
            eventbridge_sqs_event,
            6527209323865742984,
            14276854885394865473,
            "2ee7d9862d048173",
        )

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data_sns(self):
        """Test step function trace data extraction through SNS"""
        sns_event = {
            "Records": [
                {
                    "EventSource": "aws:sns",
                    "EventVersion": "1.0",
                    "EventSubscriptionArn": "arn:aws:sns:sa-east-1:425362996713:logs-to-traces-dev-topic:f1653ba3-2ff7-4c8e-9381-45a7a62f9708",
                    "Sns": {
                        "Type": "Notification",
                        "MessageId": "7bc0c17d-bf88-5ff4-af7f-a131463a0d90",
                        "TopicArn": "arn:aws:sns:sa-east-1:425362996713:logs-to-traces-dev-topic",
                        "Subject": None,
                        "Message": "{}",
                        "Timestamp": "2025-03-13T15:19:14.245Z",
                        "SignatureVersion": "1",
                        "Signature": "r8RoYzq4uNcq0yj7sxcp8sTbFiDk8zqtocG7mJuE2MPVuR8O5eNg2ohofokUnC84xADlCq5k6ElP55lbbY36tQO+qDGdV6+TGN4bAL9FiQrDE6tQYYJdlv/sYE7iOOgnRBC9ljEdCIDNtQNGCfND/8JzatPg8KAy7xMRcLrGWu4xIMEysqNTz7rETfhdZjLQPssAht44KcoUJCH4/VuB+B9W1RhwA+M8Q3tqxzahIXzcgDM8OlmfkBlXo4FDVF3WUzjXLf9AMOg+66GupjQFtUpmRMkA8KXSV1HCso7e6nIIWtOnUoWeDDUfQPFFq4TNSlb6h2NuebaHdnW5nhxnJQ==",
                        "SigningCertUrl": "https://sns.sa-east-1.amazonaws.com/SimpleNotificationService-9c6465fa7f48f5cacd23014631ec1136.pem",
                        "UnsubscribeUrl": "https://sns.sa-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:sa-east-1:425362996713:logs-to-traces-dev-topic:f1653ba3-2ff7-4c8e-9381-45a7a62f9708",
                        "MessageAttributes": {
                            "_datadog": {
                                "Type": "String",
                                "Value": '{"Execution":{"Id":"arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:11623e4f-70ee-4330-8fbe-955152dea54c","StartTime":"2025-03-13T15:19:14.019Z","Name":"11623e4f-70ee-4330-8fbe-955152dea54c","RoleArn":"arn:aws:iam::425362996713:role/service-role/StepFunctions-abhinav-activity-state-machine-role-22jpbgl6j","RedriveCount":0},"StateMachine":{"Id":"arn:aws:states:sa-east-1:425362996713:stateMachine:abhinav-inner-state-machine","Name":"abhinav-inner-state-machine"},"State":{"Name":"SNS Publish","EnteredTime":"2025-03-13T15:19:14.061Z","RetryCount":0},"RootExecutionId":"arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:11623e4f-70ee-4330-8fbe-955152dea54c","serverless-version":"v1"}',
                            }
                        },
                    },
                }
            ]
        }
        self._test_step_function_trace_data_common(
            sns_event, 1459500239678510857, 13193042003602978730, "fafc98885fd4647"
        )

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data_sns_sqs(self):
        """Test step function trace data extraction through SNS and SQS"""
        sns_sqs_event = {
            "Records": [
                {
                    "messageId": "9ec3339f-cd1a-43ba-9681-3e9113b430d3",
                    "receiptHandle": "AQEBJ5gIvqEWQt39NHPMAoK57cGgKtrgTtckWeWdDRi2FeucYr6pBhNjzXuUrmoHZMozX1WaoABtfQ5+kX5ucDBpA2Ci3Q07Z4MYvA6X0Sw13HCkiBnLrHPmH/F3rUBjvdRkIIKqA2ACX58MdkaYGNpqsHTJHB613wa8z4zurK0u7eUIXrr+e+gtsuPD39hiWlJo7cpBVv7y178rzMX8gPQTnRJv1cjhCHENtjWTSmfFC5N+BIQNIcjFsTTDRSovZlNIfAEuS+uowgzk0DUyoTJD5nFTL8lQHeXGRCUQe58/UY9OwRXEFVPGZOQR4OI9Wa4Kf/keFypTk9YwC9DhSeKvzZ0wBvejyl1n0ztT45+XYoWfi0mxGWM5b7r9wT36RDmjnM6vszH/d3fhZSRPASxWBQ==",
                    "body": '{\n  "Type" : "Notification",\n  "MessageId" : "1f3078d0-c792-5cf3-a130-189c3b846a3f",\n  "TopicArn" : "arn:aws:sns:sa-east-1:425362996713:logs-to-traces-dev-topic",\n  "Message" : "{}",\n  "Timestamp" : "2025-03-13T15:29:26.348Z",\n  "SignatureVersion" : "1",\n  "Signature" : "mxOqAQ5o/isJrMS0PezHKRaA3g8Z/8YDbkToqhJub6I66LGtl+NYhyfTyllbgxvRP2XD2meKPRSgPI3nLyq8UHsWgyYwe3Tsv8QpRunCVE9Pebh+V1LGPWfjOiL0e+bnaj956QJD99560LJ6bzWP9QO584/zfOdcw6E5XQZfAI+pvEsf28Dy0WJO/lWTATRZDf8wGhmc7uKI1ZMsrOaNoUD8PXVqsI4yrJHxhzMb3SrC7YjI/PnNIbcn6ezwprbUdbZvyNAfJiE0k5IlppA089tMXC/ItgC7AgQhG9huPdKi5KdWGACK7gEwqmFwL+5T33sUXDaH2g58WhCs76pKEw==",\n  "SigningCertURL" : "https://sns.sa-east-1.amazonaws.com/SimpleNotificationService-9c6465fa7f48f5cacd23014631ec1136.pem",\n  "UnsubscribeURL" : "https://sns.sa-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:sa-east-1:425362996713:logs-to-traces-dev-topic:5f64545d-ae9a-4a5f-a7ee-798a0bd8519e",\n  "MessageAttributes" : {\n    "_datadog" : {"Type":"String","Value":"{\\"Execution\\":{\\"Id\\":\\"arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:37ff72b8-0ee0-49e2-93c0-8a1764206a03\\",\\"StartTime\\":\\"2025-03-13T15:29:26.144Z\\",\\"Name\\":\\"37ff72b8-0ee0-49e2-93c0-8a1764206a03\\",\\"RoleArn\\":\\"arn:aws:iam::425362996713:role/service-role/StepFunctions-abhinav-activity-state-machine-role-22jpbgl6j\\",\\"RedriveCount\\":0},\\"StateMachine\\":{\\"Id\\":\\"arn:aws:states:sa-east-1:425362996713:stateMachine:abhinav-inner-state-machine\\",\\"Name\\":\\"abhinav-inner-state-machine\\"},\\"State\\":{\\"Name\\":\\"SNS Publish\\",\\"EnteredTime\\":\\"2025-03-13T15:29:26.182Z\\",\\"RetryCount\\":0},\\"RootExecutionId\\":\\"arn:aws:states:sa-east-1:425362996713:execution:abhinav-inner-state-machine:37ff72b8-0ee0-49e2-93c0-8a1764206a03\\",\\"serverless-version\\":\\"v1\\"}"}\n  }\n}',
                    "attributes": {
                        "ApproximateReceiveCount": "1",
                        "SentTimestamp": "1741879766424",
                        "SenderId": "AIDAIOA2GYWSHW4E2VXIO",
                        "ApproximateFirstReceiveTimestamp": "1741879766432",
                    },
                    "messageAttributes": {},
                    "md5OfBody": "52af59de28507d7e67324b46c95337d8",
                    "eventSource": "aws:sqs",
                    "eventSourceARN": "arn:aws:sqs:sa-east-1:425362996713:abhinav-q",
                    "awsRegion": "sa-east-1",
                }
            ]
        }
        self._test_step_function_trace_data_common(
            sns_sqs_event, 5708348677301000120, 18223515719478572006, "45457f5f3fde3fa1"
        )


class TestXRayContextConversion(unittest.TestCase):
    def test_convert_xray_trace_id(self):
        self.assertEqual(
            _convert_xray_trace_id("00000000e1be46a994272793"), 7043144561403045779
        )

        self.assertEqual(
            _convert_xray_trace_id("bd862e3fe1be46a994272793"), 7043144561403045779
        )

        self.assertEqual(
            _convert_xray_trace_id("ffffffffffffffffffffffff"),
            9223372036854775807,  # 0x7FFFFFFFFFFFFFFF
        )

    def test_convert_xray_entity_id(self):
        self.assertEqual(
            _convert_xray_entity_id("53995c3f42cd8ad8"), 6023947403358210776
        )

        self.assertEqual(
            _convert_xray_entity_id("1000000000000000"), 1152921504606846976
        )

        self.assertEqual(
            _convert_xray_entity_id("ffffffffffffffff"), 18446744073709551615
        )

    def test_convert_xray_sampling(self):
        self.assertEqual(_convert_xray_sampling(True), SamplingPriority.USER_KEEP)

        self.assertEqual(_convert_xray_sampling(False), SamplingPriority.USER_REJECT)


class TestLogsInjection(unittest.TestCase):
    def setUp(self):
        patcher = patch("datadog_lambda.tracing.get_dd_trace_context_obj")
        self.mock_get_dd_trace_context = patcher.start()
        self.mock_get_dd_trace_context.return_value = Context(
            trace_id=int(fake_xray_header_value_root_decimal),
            span_id=int(fake_xray_header_value_parent_decimal),
            sampling_priority=1,
        )
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.config.Config.is_lambda_context")
        self.mock_is_lambda_context = patcher.start()
        self.mock_is_lambda_context.return_value = True
        self.addCleanup(patcher.stop)

    @patch("datadog_lambda.config.Config.trace_enabled", False)
    def test_set_correlation_ids(self):
        set_correlation_ids()
        span = tracer.current_span()
        self.assertEqual(span.trace_id, int(fake_xray_header_value_root_decimal))
        self.assertEqual(span.parent_id, int(fake_xray_header_value_parent_decimal))
        span.finish()

    def test_set_correlation_ids_handle_empty_trace_context(self):
        # neither x-ray or ddtrace is used. no tracing context at all.
        self.mock_get_dd_trace_context.return_value = Context()
        # no exception thrown
        set_correlation_ids()
        span = tracer.current_span()
        self.assertIsNone(span)


class TestFunctionSpanTags(unittest.TestCase):
    def test_function(self):
        ctx = get_mock_context()
        span = create_function_execution_span(
            context=ctx,
            function_name="",
            is_cold_start=False,
            is_proactive_init=False,
            trace_context_source={"source": ""},
            merge_xray_traces=False,
            trigger_tags={},
            span_pointers=None,
        )
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(span.get_tag("function_version"), "$LATEST")
        self.assertEqual(span.get_tag("resource_names"), "Function")
        self.assertEqual(span.get_tag("functionname"), "function")
        self.assertEqual(span._links, [])

    def test_function_with_version(self):
        function_version = "1"
        ctx = get_mock_context(
            invoked_function_arn=function_arn + ":" + function_version
        )
        span = create_function_execution_span(
            context=ctx,
            function_name="",
            is_cold_start=False,
            is_proactive_init=False,
            trace_context_source={"source": ""},
            merge_xray_traces=False,
            trigger_tags={},
        )
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(span.get_tag("function_version"), function_version)
        self.assertEqual(span.get_tag("resource_names"), "Function")
        self.assertEqual(span.get_tag("functionname"), "function")

    def test_function_with_alias(self):
        function_alias = "alias"
        ctx = get_mock_context(invoked_function_arn=function_arn + ":" + function_alias)
        span = create_function_execution_span(
            context=ctx,
            function_name="",
            is_cold_start=False,
            is_proactive_init=False,
            trace_context_source={"source": ""},
            merge_xray_traces=False,
            trigger_tags={},
        )
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(span.get_tag("function_version"), function_alias)
        self.assertEqual(span.get_tag("resource_names"), "Function")
        self.assertEqual(span.get_tag("functionname"), "function")

    def test_function_with_trigger_tags(self):
        ctx = get_mock_context()
        span = create_function_execution_span(
            context=ctx,
            function_name="",
            is_cold_start=False,
            is_proactive_init=False,
            trace_context_source={"source": ""},
            merge_xray_traces=False,
            trigger_tags={"function_trigger.event_source": "cloudwatch-logs"},
        )
        self.assertEqual(span.get_tag("function_arn"), function_arn)
        self.assertEqual(span.get_tag("resource_names"), "Function")
        self.assertEqual(span.get_tag("functionname"), "function")
        self.assertEqual(
            span.get_tag("function_trigger.event_source"), "cloudwatch-logs"
        )

    def test_function_with_span_pointers(self):
        ctx = get_mock_context()
        span = create_function_execution_span(
            context=ctx,
            function_name="",
            is_cold_start=False,
            is_proactive_init=False,
            trace_context_source={"source": ""},
            merge_xray_traces=False,
            trigger_tags={},
            span_pointers=[
                _SpanPointerDescription(
                    pointer_kind="some.kind",
                    pointer_direction=_SpanPointerDirection.UPSTREAM,
                    pointer_hash="some.hash",
                    extra_attributes={},
                ),
                _SpanPointerDescription(
                    pointer_kind="other.kind",
                    pointer_direction=_SpanPointerDirection.DOWNSTREAM,
                    pointer_hash="other.hash",
                    extra_attributes={"extra": "stuff"},
                ),
            ],
        )
        self.assertEqual(
            span._links,
            [
                _SpanPointer(
                    pointer_kind="some.kind",
                    pointer_direction=_SpanPointerDirection.UPSTREAM,
                    pointer_hash="some.hash",
                    extra_attributes={},
                ),
                _SpanPointer(
                    pointer_kind="other.kind",
                    pointer_direction=_SpanPointerDirection.DOWNSTREAM,
                    pointer_hash="other.hash",
                    extra_attributes={"extra": "stuff"},
                ),
            ],
        )


class TestSetTraceRootSpan(unittest.TestCase):
    def setUp(self):
        os.environ["_X_AMZN_TRACE_ID"] = fake_xray_header_value
        patcher = patch("datadog_lambda.tracing.send_segment")
        self.mock_send_segment = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch("datadog_lambda.config.Config.is_lambda_context")
        self.mock_is_lambda_context = patcher.start()
        self.mock_is_lambda_context.return_value = True
        self.addCleanup(patcher.stop)
        patcher = patch("datadog_lambda.tracing.tracer.context_provider.activate")
        self.mock_activate = patcher.start()
        self.mock_activate.return_value = True
        self.addCleanup(patcher.stop)
        patcher = patch("datadog_lambda.tracing.dd_trace_context", None)
        self.mock_dd_trace_context = patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
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

    def test_set_dd_trace_py_root_no_span_id(self):
        os.environ["_X_AMZN_TRACE_ID"] = "Root=1-5e272390-8c398be037738dc042009320"

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
        set_dd_trace_py_root(TraceContextSource.EVENT, True)

        expected_context = Context(
            trace_id=123,  # Trace Id from incomming context
            span_id=321,  # Span Id from incoming context
            sampling_priority=1,  # Sampling priority from incomming context
        )
        self.mock_activate.assert_called()
        self.mock_activate.assert_has_calls([call(expected_context)])

    def test_set_dd_trace_py_root_none_context(self):
        set_dd_trace_py_root(TraceContextSource.EVENT, True)
        self.mock_activate.assert_not_called()


class TestServiceMapping(unittest.TestCase):
    def setUp(self):
        self.service_mapping = {}

    def get_service_mapping(self):
        return global_service_mapping

    def set_service_mapping(self, new_service_mapping):
        global_service_mapping.clear()
        global_service_mapping.update(new_service_mapping)

    def test_create_service_mapping_invalid_input(self):
        # Test case where the input is a string without a colon to split on
        val = "api1"
        self.assertEqual(create_service_mapping(val), {})

        # Test case where the input is an empty string
        val = ""
        self.assertEqual(create_service_mapping(val), {})

        # Test case where the key and value are identical
        val = "api1:api1"
        self.assertEqual(create_service_mapping(val), {})

        # Test case where the key or value is missing
        val = ":api1"
        self.assertEqual(create_service_mapping(val), {})
        val = "api1:"
        self.assertEqual(create_service_mapping(val), {})

    def test_create_service_mapping(self):
        val = "api1:service1,api2:service2"
        expected_output = {"api1": "service1", "api2": "service2"}
        self.assertEqual(create_service_mapping(val), expected_output)

    def test_get_service_mapping(self):
        os.environ["DD_SERVICE_MAPPING"] = "api1:service1,api2:service2"
        expected_output = {"api1": "service1", "api2": "service2"}
        self.set_service_mapping(
            create_service_mapping(os.environ["DD_SERVICE_MAPPING"])
        )
        self.assertEqual(self.get_service_mapping(), expected_output)
        del os.environ["DD_SERVICE_MAPPING"]

    def test_set_service_mapping(self):
        new_service_mapping = {"api3": "service3", "api4": "service4"}
        self.set_service_mapping(new_service_mapping)
        self.assertEqual(self.get_service_mapping(), new_service_mapping)

    def test_determine_service_name(self):
        # Prepare the environment
        os.environ["DD_SERVICE_MAPPING"] = "api1:service1,api2:service2"
        self.set_service_mapping(
            create_service_mapping(os.environ["DD_SERVICE_MAPPING"])
        )

        # Case where specific key is in the service mapping
        specific_key = "api1"
        self.assertEqual(
            determine_service_name(
                self.get_service_mapping(), specific_key, "lambda_url", "default"
            ),
            "service1",
        )

        # Case where specific key is not in the service mapping, but generic key is
        specific_key = "api3"
        self.assertEqual(
            determine_service_name(
                self.get_service_mapping(), specific_key, "api2", "default"
            ),
            "service2",
        )

        # Case where neither specific nor generic keys are in the service mapping
        specific_key = "api3"
        self.assertEqual(
            determine_service_name(
                self.get_service_mapping(), specific_key, "api3", "default"
            ),
            "default",
        )

        # Test with DD_TRACE_AWS_SERVICE_REPRESENTATION_ENABLED set to false
        os.environ["DD_TRACE_AWS_SERVICE_REPRESENTATION_ENABLED"] = "false"
        self.assertEqual(
            determine_service_name(
                self.get_service_mapping(), "api4", "api4", "extracted", "fallback"
            ),
            "fallback",
        )

        # Test with DD_TRACE_AWS_SERVICE_REPRESENTATION_ENABLED set to 0
        os.environ["DD_TRACE_AWS_SERVICE_REPRESENTATION_ENABLED"] = "0"
        self.assertEqual(
            determine_service_name(
                self.get_service_mapping(), "api4", "api4", "extracted", "fallback"
            ),
            "fallback",
        )

        # Test with DD_TRACE_AWS_SERVICE_REPRESENTATION_ENABLED not set (default behavior)
        if "DD_TRACE_AWS_SERVICE_REPRESENTATION_ENABLED" in os.environ:
            del os.environ["DD_TRACE_AWS_SERVICE_REPRESENTATION_ENABLED"]
        self.assertEqual(
            determine_service_name(
                self.get_service_mapping(), "api4", "api4", "extracted", "fallback"
            ),
            "extracted",
        )

        # Test with empty extracted key
        self.assertEqual(
            determine_service_name(
                self.get_service_mapping(), "api4", "api4", "  ", "fallback"
            ),
            "fallback",
        )

        del os.environ["DD_SERVICE_MAPPING"]

    def test_remaps_all_inferred_span_service_names_from_api_gateway_event(self):
        new_service_mapping = {"lambda_api_gateway": "new-name"}
        self.set_service_mapping(new_service_mapping)
        event_sample_source = "api-gateway"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["requestContext"][
            "domainName"
        ] = "different.execute-api.us-east-2.amazonaws.com"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.service, "new-name")

    def test_remaps_specific_inferred_span_service_names_from_api_gateway_event(
        self,
    ):
        new_service_mapping = {"1234567890": "new-name"}
        self.set_service_mapping(new_service_mapping)
        event_sample_source = "api-gateway"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["requestContext"]["apiId"] = "different"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(
            span2.service, "70ixmpl4fl.execute-api.us-east-2.amazonaws.com"
        )

    def test_remaps_specific_inferred_span_service_names_from_api_gateway_websocket_event(
        self,
    ):
        self.set_service_mapping({"p62c47itsb": "new-name"})
        event_sample_source = "api-gateway-websocket-default"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.apigateway.websocket")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["requestContext"]["apiId"] = "different"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.apigateway.websocket")
        self.assertEqual(
            span2.service, "p62c47itsb.execute-api.eu-west-1.amazonaws.com"
        )

    def test_remaps_specific_inferred_span_service_names_from_api_gateway_http_event(
        self,
    ):
        self.set_service_mapping({"x02yirxc7a": "new-name"})
        event_sample_source = "http-api"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["requestContext"]["apiId"] = "different"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(
            span2.service, "x02yirxc7a.execute-api.eu-west-1.amazonaws.com"
        )

    def test_remaps_all_inferred_span_service_names_from_lambda_url_event(self):
        self.set_service_mapping({"lambda_url": "new-name"})
        event_sample_source = "lambda-url"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.lambda.url")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["requestContext"][
            "domainName"
        ] = "different.lambda-url.eu-south-1.amazonaws.com"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.lambda.url")
        self.assertEqual(span2.service, "new-name")

    def test_remaps_specific_inferred_span_service_names_from_lambda_url_event(
        self,
    ):
        self.set_service_mapping({"a8hyhsshac": "new-name"})
        event_sample_source = "lambda-url"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.lambda.url")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["requestContext"]["apiId"] = "different"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.lambda.url")
        self.assertEqual(
            span2.service, "a8hyhsshac.lambda-url.eu-south-1.amazonaws.com"
        )

    def test_remaps_all_inferred_span_service_names_from_sqs_event(self):
        self.set_service_mapping({"lambda_sqs": "new-name"})
        event_sample_source = "sqs-string-msg-attribute"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.sqs")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["Records"][0][
            "eventSourceARN"
        ] = "arn:aws:sqs:eu-west-1:123456789012:different-sqs-url"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.sqs")
        self.assertEqual(span2.service, "new-name")

    def test_remaps_specific_inferred_span_service_names_from_sqs_event(self):
        self.set_service_mapping({"InferredSpansQueueNode": "new-name"})
        event_sample_source = "sqs-string-msg-attribute"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.sqs")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["Records"][0][
            "eventSourceARN"
        ] = "arn:aws:sqs:eu-west-1:123456789012:different-sqs-url"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.sqs")
        self.assertEqual(span2.service, "different-sqs-url")

    def test_remaps_all_inferred_span_service_names_from_sns_event(self):
        self.set_service_mapping({"lambda_sns": "new-name"})
        event_sample_source = "sns-string-msg-attribute"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.sns")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["Records"][0]["Sns"][
            "TopicArn"
        ] = "arn:aws:sns:us-west-2:123456789012:different-sns-topic"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.sns")
        self.assertEqual(span2.service, "new-name")

    def test_remaps_specific_inferred_span_service_names_from_sns_event(self):
        self.set_service_mapping({"serverlessTracingTopicPy": "new-name"})
        event_sample_source = "sns-string-msg-attribute"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.sns")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["Records"][0]["Sns"][
            "TopicArn"
        ] = "arn:aws:sns:us-west-2:123456789012:different-sns-topic"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.sns")
        self.assertEqual(span2.service, "different-sns-topic")

    def test_remaps_all_inferred_span_service_names_from_kinesis_event(self):
        self.set_service_mapping({"lambda_kinesis": "new-name"})
        event_sample_source = "kinesis"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.kinesis")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["Records"][0][
            "eventSourceARN"
        ] = "arn:aws:kinesis:eu-west-1:601427279990:stream/differentKinesisStream"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.kinesis")
        self.assertEqual(span2.service, "new-name")

    def test_remaps_specific_inferred_span_service_names_from_kinesis_event(self):
        self.set_service_mapping({"Different_EXAMPLE": "new-name"})
        event_sample_source = "kinesis"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.kinesis")
        self.assertEqual(span1.service, "kinesisStream")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["Records"][0][
            "eventSourceARN"
        ] = "arn:aws:kinesis:eu-west-1:601427279990:stream/DifferentKinesisStream"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.kinesis")
        self.assertEqual(span2.service, "DifferentKinesisStream")

    def test_remaps_all_inferred_span_service_names_from_s3_event(self):
        self.set_service_mapping({"lambda_s3": "new-name"})
        event_sample_source = "s3"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.s3")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["Records"][0]["s3"]["bucket"][
            "arn"
        ] = "arn:aws:s3:::different-example-bucket"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.s3")
        self.assertEqual(span2.service, "new-name")

    def test_remaps_specific_inferred_span_service_names_from_s3_event(self):
        self.set_service_mapping({"example-bucket": "new-name"})
        event_sample_source = "s3"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.s3")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["Records"][0]["s3"]["bucket"]["name"] = "different-example-bucket"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.s3")
        self.assertEqual(span2.service, "different-example-bucket")

    def test_remaps_all_inferred_span_service_names_from_dynamodb_event(self):
        self.set_service_mapping({"lambda_dynamodb": "new-name"})
        event_sample_source = "dynamodb"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.dynamodb")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["Records"][0][
            "eventSourceARN"
        ] = "arn:aws:dynamodb:us-east-1:123456789012:table/DifferentExampleTableWithStream/stream/2015-06-27T00:48:05.899"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.dynamodb")
        self.assertEqual(span2.service, "new-name")

    def test_remaps_specific_inferred_span_service_names_from_dynamodb_event(self):
        self.set_service_mapping({"ExampleTableWithStream": "new-name"})
        event_sample_source = "dynamodb"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.dynamodb")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["Records"][0][
            "eventSourceARN"
        ] = "arn:aws:dynamodb:us-east-1:123456789012:table/DifferentExampleTableWithStream/stream/2015-06-27T00:48:05.899"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.dynamodb")
        self.assertEqual(span2.service, "DifferentExampleTableWithStream")

    def test_remaps_all_inferred_span_service_names_from_eventbridge_event(self):
        self.set_service_mapping({"lambda_eventbridge": "new-name"})
        event_sample_source = "eventbridge-custom"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.eventbridge")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["source"] = "different.eventbridge.custom.event.sender"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.eventbridge")
        self.assertEqual(span2.service, "new-name")

    def test_remaps_specific_inferred_span_service_names_from_eventbridge_event(
        self,
    ):
        self.set_service_mapping({"eventbridge.custom.event.sender": "new-name"})
        event_sample_source = "eventbridge-custom"
        test_file = event_samples + event_sample_source + ".json"
        with open(test_file, "r") as event:
            original_event = json.load(event)

        ctx = get_mock_context()
        ctx.aws_request_id = "123"

        span1 = create_inferred_span(original_event, ctx)
        self.assertEqual(span1.get_tag("operation_name"), "aws.eventbridge")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["source"] = "different.eventbridge.custom.event.sender"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.eventbridge")
        self.assertEqual(span2.service, "different.eventbridge.custom.event.sender")


class _Span(object):
    def __init__(self, service, start, span_type, parent_name=None, tags=None):
        self.service = service
        self.start = start
        self.span_type = span_type
        self.parent_name = parent_name
        self.tags = tags or {}


_test_create_inferred_span = (
    (
        "api-gateway",
        _Span(
            service="70ixmpl4fl.execute-api.us-east-2.amazonaws.com",
            start=1428582896.0,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "1234567890",
                "apiname": "1234567890",
                "endpoint": "/path/to/resource",
                "http.method": "POST",
                "http.url": "https://70ixmpl4fl.execute-api.us-east-2.amazonaws.com/path/to/resource",
                "http.useragent": "Custom User Agent String",
                "request_id": "123",
                "resource_names": "POST /{proxy+}",
                "stage": "prod",
            },
        ),
    ),
    (
        "api-gateway-non-proxy-async",
        _Span(
            service="lgxbo6a518.execute-api.eu-west-1.amazonaws.com",
            start=1631210915.2510002,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "async",
                "_inferred_span.tag_source": "self",
                "apiid": "lgxbo6a518",
                "apiname": "lgxbo6a518",
                "endpoint": "/http/get",
                "http.method": "GET",
                "http.url": "https://lgxbo6a518.execute-api.eu-west-1.amazonaws.com/http/get",
                "http.useragent": "curl/7.64.1",
                "request_id": "123",
                "resource_names": "GET /http/get",
                "stage": "dev",
            },
        ),
    ),
    (
        "api-gateway-non-proxy",
        _Span(
            service="lgxbo6a518.execute-api.eu-west-1.amazonaws.com",
            start=1631210915.2510002,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "lgxbo6a518",
                "apiname": "lgxbo6a518",
                "endpoint": "/http/get",
                "http.method": "GET",
                "http.url": "https://lgxbo6a518.execute-api.eu-west-1.amazonaws.com/http/get",
                "http.useragent": "curl/7.64.1",
                "request_id": "123",
                "resource_names": "GET /http/get",
                "stage": "dev",
            },
        ),
    ),
    (
        "http-api",
        _Span(
            service="x02yirxc7a.execute-api.eu-west-1.amazonaws.com",
            start=1631212283.738,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "x02yirxc7a",
                "apiname": "x02yirxc7a",
                "endpoint": "/httpapi/get",
                "http.method": "GET",
                "http.protocol": "HTTP/1.1",
                "http.source_ip": "38.122.226.210",
                "http.url": "https://x02yirxc7a.execute-api.eu-west-1.amazonaws.com/httpapi/get",
                "http.useragent": "curl/7.64.1",
                "request_id": "123",
                "resource_names": "GET /httpapi/get",
                "stage": "$default",
            },
        ),
    ),
    (
        "api-gateway-v1-parametrized",
        _Span(
            service="mcwkra0ya4.execute-api.sa-east-1.amazonaws.com",
            start=1710529824.52,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "mcwkra0ya4",
                "apiname": "mcwkra0ya4",
                "endpoint": "/user/42",
                "http.method": "GET",
                "http.url": "https://mcwkra0ya4.execute-api.sa-east-1.amazonaws.com/user/42",
                "http.useragent": "curl/8.1.2",
                "request_id": "123",
                "resource_names": "GET /user/{id}",
                "stage": "dev",
            },
        ),
    ),
    (
        "api-gateway-v2-parametrized",
        _Span(
            service="9vj54we5ih.execute-api.sa-east-1.amazonaws.com",
            start=1710529905.066,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "9vj54we5ih",
                "apiname": "9vj54we5ih",
                "endpoint": "/user/42",
                "http.method": "GET",
                "http.url": "https://9vj54we5ih.execute-api.sa-east-1.amazonaws.com/user/42",
                "http.useragent": "curl/8.1.2",
                "request_id": "123",
                "resource_names": "GET /user/{id}",
                "stage": "$default",
            },
        ),
    ),
    (
        "api-gateway-websocket-default",
        _Span(
            service="p62c47itsb.execute-api.eu-west-1.amazonaws.com",
            start=1631285061.365,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "p62c47itsb",
                "apiname": "p62c47itsb",
                "connection_id": "Fc5SzcoYGjQCJlg=",
                "endpoint": "$default",
                "event_type": "MESSAGE",
                "http.url": "https://p62c47itsb.execute-api.eu-west-1.amazonaws.com$default",
                "message_direction": "IN",
                "operation_name": "aws.apigateway.websocket",
                "request_id": "123",
                "resource_names": "$default",
                "stage": "dev",
            },
        ),
    ),
    (
        "api-gateway-websocket-connect",
        _Span(
            service="p62c47itsb.execute-api.eu-west-1.amazonaws.com",
            start=1631284003.071,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "p62c47itsb",
                "apiname": "p62c47itsb",
                "connection_id": "Fc2tgfl3mjQCJfA=",
                "endpoint": "$connect",
                "event_type": "CONNECT",
                "http.url": "https://p62c47itsb.execute-api.eu-west-1.amazonaws.com$connect",
                "message_direction": "IN",
                "operation_name": "aws.apigateway.websocket",
                "request_id": "123",
                "resource_names": "$connect",
                "stage": "dev",
            },
        ),
    ),
    (
        "api-gateway-websocket-disconnect",
        _Span(
            service="p62c47itsb.execute-api.eu-west-1.amazonaws.com",
            start=1631284034.737,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "p62c47itsb",
                "apiname": "p62c47itsb",
                "connection_id": "Fc2tgfl3mjQCJfA=",
                "endpoint": "$disconnect",
                "event_type": "DISCONNECT",
                "http.url": "https://p62c47itsb.execute-api.eu-west-1.amazonaws.com$disconnect",
                "message_direction": "IN",
                "operation_name": "aws.apigateway.websocket",
                "request_id": "123",
                "resource_names": "$disconnect",
                "stage": "dev",
            },
        ),
    ),
    (
        "sqs-string-msg-attribute",
        _Span(
            service="InferredSpansQueueNode",
            start=1634662094.538,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "async",
                "_inferred_span.tag_source": "self",
                "event_source_arn": "arn:aws:sqs:eu-west-1:601427279990:InferredSpansQueueNode",
                "operation_name": "aws.sqs",
                "queuename": "InferredSpansQueueNode",
                "resource_names": "InferredSpansQueueNode",
                "sender_id": "AROAYYB64AB3LSVUYFP5T:harv-inferred-spans-dev-initSender",
            },
        ),
    ),
    (
        "sns-string-msg-attribute",
        _Span(
            service="serverlessTracingTopicPy",
            start=1643638421.637,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "async",
                "_inferred_span.tag_source": "self",
                "message_id": "87056a47-f506-5d77-908b-303605d3b197",
                "operation_name": "aws.sns",
                "resource_names": "serverlessTracingTopicPy",
                "topic_arn": "arn:aws:sns:eu-west-1:601427279990:serverlessTracingTopicPy",
                "topicname": "serverlessTracingTopicPy",
                "type": "Notification",
            },
        ),
    ),
    (
        "sns-b64-msg-attribute",
        _Span(
            service="serverlessTracingTopicPy",
            start=1643638421.637,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "async",
                "_inferred_span.tag_source": "self",
                "message_id": "87056a47-f506-5d77-908b-303605d3b197",
                "operation_name": "aws.sns",
                "resource_names": "serverlessTracingTopicPy",
                "topic_arn": "arn:aws:sns:eu-west-1:601427279990:serverlessTracingTopicPy",
                "topicname": "serverlessTracingTopicPy",
                "type": "Notification",
            },
        ),
    ),
    (
        "kinesisStream",
        _Span(
            service="kinesisStream",
            start=1643638425.163,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "async",
                "_inferred_span.tag_source": "self",
                "endpoint": None,
                "event_id": "shardId-000000000002:49624230154685806402418173680709770494154422022871973922",
                "event_name": "aws:kinesis:record",
                "event_source_arn": "arn:aws:kinesis:eu-west-1:601427279990:stream/kinesisStream",
                "event_version": "1.0",
                "http.method": None,
                "http.url": None,
                "operation_name": "aws.kinesis",
                "partition_key": "partitionkey",
                "request_id": None,
                "resource_names": "kinesisStream",
                "shardid": "shardId-000000000002",
                "streamname": "kinesisStream",
            },
        ),
    ),
    (
        "dynamodb",
        _Span(
            service="ExampleTableWithStream",
            start=1428537600.0,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "async",
                "_inferred_span.tag_source": "self",
                "endpoint": None,
                "event_id": "c4ca4238a0b923820dcc509a6f75849b",
                "event_name": "INSERT",
                "event_source_arn": "arn:aws:dynamodb:us-east-1:123456789012:table/ExampleTableWithStream/stream/2015-06-27T00:48:05.899",
                "event_version": "1.1",
                "http.method": None,
                "http.url": None,
                "operation_name": "aws.dynamodb",
                "request_id": None,
                "resource_names": "ExampleTableWithStream",
                "size_bytes": "26",
                "stream_view_type": "NEW_AND_OLD_IMAGES",
                "tablename": "ExampleTableWithStream",
            },
        ),
    ),
    (
        "s3",
        _Span(
            service="example-bucket",
            start=0.0,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "async",
                "_inferred_span.tag_source": "self",
                "bucket_arn": "arn:aws:s3:::example-bucket",
                "bucketname": "example-bucket",
                "endpoint": None,
                "event_name": "ObjectCreated:Put",
                "http.method": None,
                "http.url": None,
                "object_etag": "0123456789abcdef0123456789abcdef",
                "object_key": "test/key",
                "object_size": "1024",
                "operation_name": "aws.s3",
                "request_id": None,
                "resource_names": "example-bucket",
            },
        ),
    ),
    (
        "eventbridge-custom",
        _Span(
            service="eventbridge.custom.event.sender",
            start=1635989865.0,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "async",
                "_inferred_span.tag_source": "self",
                "endpoint": None,
                "http.method": None,
                "http.url": None,
                "operation_name": "aws.eventbridge",
                "request_id": None,
                "resource_names": "eventbridge.custom.event.sender",
            },
        ),
    ),
    (
        "eventbridge-sqs",
        _Span(
            service="eventbridge-sqs-queue",
            start=1691102943.638,
            span_type="web",
            parent_name="aws.eventbridge",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "async",
                "_inferred_span.tag_source": "self",
                "endpoint": None,
                "event_source_arn": "arn:aws:sqs:us-east-1:425362996713:eventbridge-sqs-queue",
                "http.method": None,
                "http.url": None,
                "operation_name": "aws.sqs",
                "queuename": "eventbridge-sqs-queue",
                "request_id": None,
                "resource_names": "eventbridge-sqs-queue",
                "sender_id": "AIDAJXNJGGKNS7OSV23OI",
            },
        ),
    ),
    (
        "api-gateway-no-apiid",
        _Span(
            service="70ixmpl4fl.execute-api.us-east-2.amazonaws.com",
            start=1428582896.0,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "None",
                "apiname": "None",
                "endpoint": "/path/to/resource",
                "http.method": "POST",
                "http.url": "https://70ixmpl4fl.execute-api.us-east-2.amazonaws.com/path/to/resource",
                "http.useragent": "Custom User Agent String",
                "request_id": "123",
                "resource_names": "POST /{proxy+}",
                "stage": "prod",
            },
        ),
    ),
    (
        "authorizer-request-api-gateway-v1",
        _Span(
            service="amddr1rix9.execute-api.eu-west-1.amazonaws.com",
            start=1663295021.832,
            span_type="web",
            parent_name="aws.apigateway.authorizer",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "https://amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "http.useragent": "PostmanRuntime/7.29.2",
                "request_id": "123",
                "resource_names": "GET /hello",
                "stage": "dev",
            },
        ),
    ),
    (
        "authorizer-request-api-gateway-v1-cached",
        _Span(
            service="amddr1rix9.execute-api.eu-west-1.amazonaws.com",
            start=1666714653.636,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "https://amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "http.useragent": "PostmanRuntime/7.29.2",
                "request_id": "123",
                "resource_names": "GET /hello",
                "stage": "dev",
            },
        ),
    ),
    (
        "authorizer-token-api-gateway-v1",
        _Span(
            service="amddr1rix9.execute-api.eu-west-1.amazonaws.com",
            start=1663295021.832,
            span_type="web",
            parent_name="aws.apigateway.authorizer",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "https://amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "http.useragent": "PostmanRuntime/7.29.2",
                "request_id": "123",
                "resource_names": "GET /hello",
                "stage": "dev",
            },
        ),
    ),
    (
        "authorizer-token-api-gateway-v1-cached",
        _Span(
            service="amddr1rix9.execute-api.eu-west-1.amazonaws.com",
            start=1666803622.99,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "https://amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "http.useragent": "PostmanRuntime/7.29.2",
                "request_id": "123",
                "resource_names": "GET /hello",
                "stage": "dev",
            },
        ),
    ),
    (
        "authorizer-request-api-gateway-v2",
        _Span(
            service="amddr1rix9.execute-api.eu-west-1.amazonaws.com",
            start=1664228639.5337753,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "https://amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "http.useragent": "curl/7.64.1",
                "request_id": "123",
                "resource_names": "GET /hello",
                "stage": "dev",
            },
        ),
    ),
    (
        "authorizer-request-api-gateway-v2-cached",
        _Span(
            service="amddr1rix9.execute-api.eu-west-1.amazonaws.com",
            start=1666715429.349,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "https://amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "http.useragent": "PostmanRuntime/7.29.2",
                "request_id": "123",
                "resource_names": "GET /hello",
                "stage": "dev",
            },
        ),
    ),
    (
        "authorizer-request-api-gateway-websocket-connect",
        _Span(
            service="amddr1rix9.execute-api.eu-west-1.amazonaws.com",
            start=1664388386.892,
            span_type="web",
            parent_name="aws.apigateway.authorizer",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "connection_id": "ZLr9QeNLmjQCIZA=",
                "endpoint": "$connect",
                "event_type": "CONNECT",
                "http.url": "https://amddr1rix9.execute-api.eu-west-1.amazonaws.com$connect",
                "message_direction": "IN",
                "operation_name": "aws.apigateway.websocket",
                "request_id": "123",
                "resource_names": "$connect",
                "stage": "dev",
            },
        ),
    ),
    (
        "authorizer-request-api-gateway-websocket-message",
        _Span(
            service="amddr1rix9.execute-api.eu-west-1.amazonaws.com",
            start=1664390397.1169999,
            span_type="web",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "connection_id": "ZLwtceO1mjQCI8Q=",
                "endpoint": "main",
                "event_type": "MESSAGE",
                "http.url": "https://amddr1rix9.execute-api.eu-west-1.amazonaws.commain",
                "message_direction": "IN",
                "operation_name": "aws.apigateway.websocket",
                "request_id": "123",
                "resource_names": "main",
                "stage": "dev",
            },
        ),
    ),
)


@pytest.mark.parametrize("source,expect", _test_create_inferred_span)
@patch("ddtrace.trace.Span.finish", autospec=True)
def test_create_inferred_span(mock_span_finish, source, expect):
    with open(f"{event_samples}{source}.json") as f:
        event = json.load(f)
    ctx = get_mock_context(aws_request_id="123")

    actual = create_inferred_span(event, ctx)
    assert actual.service == expect.service
    assert actual.start == expect.start
    assert actual.span_type == expect.span_type
    for tag, value in expect.tags.items():
        assert actual.get_tag(tag) == value, f"wrong value for tag {tag}"

    if expect.parent_name is not None:  # there are two inferred spans
        assert mock_span_finish.call_count == 1
        args, kwargs = mock_span_finish.call_args_list[0]
        parent = args[0]
        finish_time = kwargs.get("finish_time") or args[1]
        assert parent.name == expect.parent_name
        assert actual.parent_id == parent.span_id
        assert finish_time == expect.start
    else:  # there is only one inferred span
        assert mock_span_finish.call_count == 0


class TestInferredSpans(unittest.TestCase):
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
        mock_span = Mock(ddtrace.trace.Span)
        status_code = "500"
        mark_trace_as_error_for_5xx_responses(
            context="fake_context", status_code=status_code, span=mock_span
        )
        mock_submit_errors_metric.assert_called_once()
        self.assertEqual(1, mock_span.error)


class TestStepFunctionsTraceContext(unittest.TestCase):
    def test_deterministic_m5_hash(self):
        result = _deterministic_sha256_hash("some_testing_random_string", LOWER_64_BITS)
        self.assertEqual(7456137785171041414, result)

    def test_deterministic_m5_hash__result_the_same_as_backend_1(self):
        result = _deterministic_sha256_hash(
            "arn:aws:states:sa-east-1:425362996713:stateMachine:MyStateMachine-b276uka1j"
            "#lambda#1",
            HIGHER_64_BITS,
        )
        self.assertEqual(3711631873188331089, result)

    def test_deterministic_m5_hash__result_the_same_as_backend_2(self):
        result = _deterministic_sha256_hash(
            "arn:aws:states:sa-east-1:425362996713:stateMachine:MyStateMachine-b276uka1j"
            "#lambda#2",
            HIGHER_64_BITS,
        )
        self.assertEqual(5759173372325510050, result)

    def test_deterministic_m5_hash__always_leading_with_zero(self):
        for i in range(100):
            result = _deterministic_sha256_hash(str(i), 64)
            result_in_binary = bin(int(result))
            # Leading zeros will be omitted, so only test for full 64 bits present
            if len(result_in_binary) == 66:  # "0b" + 64 bits.
                self.assertTrue(result_in_binary.startswith("0b0"))


class TestExceptionOutsideHandler(unittest.TestCase):
    @patch("datadog_lambda.config.Config.trace_enabled", True)
    @patch("datadog_lambda.tracing.submit_errors_metric")
    @patch("time.time_ns", return_value=42)
    def test_exception_outside_handler_tracing_enabled(
        self, mock_time, mock_submit_errors_metric
    ):
        fake_error = ValueError("Some error message")
        resource_name = "my_handler"
        span_type = "aws.lambda"
        mock_span = Mock()
        with patch(
            "datadog_lambda.tracing.tracer.trace", return_value=mock_span
        ) as mock_trace:
            emit_telemetry_on_exception_outside_of_handler(
                fake_error, resource_name, 42
            )

        mock_submit_errors_metric.assert_called_once_with(None)

        mock_trace.assert_called_once_with(
            span_type,
            service="aws.lambda",
            resource=resource_name,
            span_type="serverless",
        )
        mock_span.set_tags.assert_called_once_with(
            {
                "error.status": 500,
                "error.type": "ValueError",
                "error.message": fake_error,
                "error.stack": traceback.format_exc(),
                "resource_names": resource_name,
                "resource.name": resource_name,
                "operation_name": span_type,
                "status": "error",
            }
        )
        mock_span.finish.assert_called_once()
        assert mock_span.error == 1
        assert mock_span.start_ns == 42

    @patch("datadog_lambda.config.Config.trace_enabled", False)
    @patch("datadog_lambda.tracing.submit_errors_metric")
    @patch("time.time_ns", return_value=42)
    def test_exception_outside_handler_tracing_disabled(
        self, mock_time, mock_submit_errors_metric
    ):
        fake_error = ValueError("Some error message")
        resource_name = "my_handler"
        with patch("datadog_lambda.tracing.tracer.trace") as mock_trace:
            emit_telemetry_on_exception_outside_of_handler(
                fake_error, resource_name, 42
            )

        mock_submit_errors_metric.assert_called_once_with(None)
        mock_trace.assert_not_called()


class TestExtractDDContextWithDSMLogic(unittest.TestCase):
    def setUp(self):
        checkpoint_patcher = patch("ddtrace.data_streams.set_consume_checkpoint")
        self.mock_checkpoint = checkpoint_patcher.start()
        self.addCleanup(checkpoint_patcher.stop)
        self.lambda_context = get_mock_context()
        config_patcher = patch(
            "datadog_lambda.config.Config.data_streams_enabled", True
        )
        config_patcher.start()
        self.addCleanup(config_patcher.stop)

    # SQS TESTS

    def test_sqs_context_propagated_string_value(self):
        dd_data = {"dd-pathway-ctx-base64": "12345"}
        dd_json_data = json.dumps(dd_data)

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "messageAttributes": {
                        "_datadog": {"dataType": "String", "stringValue": dd_json_data}
                    },
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

    def test_sqs_context_propagated_binary_value(self):
        dd_data = {"dd-pathway-ctx-base64": "12345"}
        dd_json_data = json.dumps(dd_data)
        encoded_data = base64.b64encode(dd_json_data.encode()).decode()

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "messageAttributes": {
                        "_datadog": {"dataType": "Binary", "binaryValue": encoded_data}
                    },
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

    def test_sqs_no_datadog_message_attribute(self):
        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "messageAttributes": {},  # No _datadog key
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )
        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_sqs_empty_datadog_message_attribute(self):
        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "messageAttributes": {
                        "_datadog": {
                            "dataType": "String",
                            "stringValue": "null",
                        }  # json.loads("null") => None
                    },
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )
        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_sqs_no_DSM_context_in_message_attribute(self):
        dd_data = {"NOT-DSM-KEY": "12345"}
        dd_json_data = json.dumps(dd_data)
        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "messageAttributes": {
                        "_datadog": {"dataType": "String", "stringValue": dd_json_data}
                    },
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    @patch("datadog_lambda.tracing.logger")
    def test_sqs_invalid_datadog_message_attribute(self, mock_logger):
        test_cases = [
            {
                "name": "invalid_base64",
                "event": {
                    "Records": [
                        {
                            "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                            "messageAttributes": {
                                "_datadog": {
                                    "dataType": "Binary",
                                    "binaryValue": "invalid-base64",
                                }
                            },
                            "eventSource": "aws:sqs",
                        }
                    ]
                },
                "expected_log": ("The trace extractor returned with error %s", ANY),
            },
            {
                "name": "unsupported_datatype",
                "event": {
                    "Records": [
                        {
                            "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                            "messageAttributes": {
                                "_datadog": {
                                    "dataType": "Number",
                                    "numberValue": 123,
                                }  # Unsupported type
                            },
                            "eventSource": "aws:sqs",
                        }
                    ]
                },
                "expected_log": (
                    "Datadog Lambda Python only supports extracting trace"
                    "context from String or Binary SQS/SNS message attributes",
                ),
            },
        ]

        for test_case in test_cases:
            with self.subTest(test_case=test_case["name"]):
                mock_logger.reset_mock()
                self.mock_checkpoint.reset_mock()

                extract_context_from_sqs_or_sns_event_or_context(
                    test_case["event"],
                    self.lambda_context,
                    parse_event_source(test_case["event"]),
                )

                # Exception triggers logger
                mock_logger.debug.assert_any_call(*test_case["expected_log"])

                self.assertEqual(self.mock_checkpoint.call_count, 1)
                args, _ = self.mock_checkpoint.call_args
                self.assertEqual(args[0], "sqs")
                self.assertEqual(
                    args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue"
                )
                carrier_get = args[2]
                # None indicates no DSM context propagation
                self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_sqs_source_arn_not_found(self):
        event = {
            "Records": [
                {
                    "eventSourceARN": "",
                    "messageAttributes": {},
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )

        self.mock_checkpoint.assert_not_called()

    @patch("datadog_lambda.config.Config.data_streams_enabled", False)
    def test_sqs_data_streams_disabled(self):
        context_json = {"dd-pathway-ctx-base64": "12345"}
        event_type = "sqs"
        arn = "arn:aws:sqs:us-east-1:123456789012:test-queue"

        _dsm_set_checkpoint(context_json, event_type, arn)

        self.mock_checkpoint.assert_not_called()

    # SNS TESTS

    def test_sns_context_propagated_string_value(self):
        dd_data = {"dd-pathway-ctx-base64": "12345"}
        dd_json_data = json.dumps(dd_data)

        event = {
            "Records": [
                {
                    "eventSourceARN": "",
                    "Sns": {
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                        "MessageAttributes": {
                            "_datadog": {"Type": "String", "Value": dd_json_data}
                        },
                    },
                    "eventSource": "aws:sns",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sns")
        self.assertEqual(args[1], "arn:aws:sns:us-east-1:123456789012:test-topic")
        carrier_get = args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

    def test_sns_context_propagated_binary_value(self):
        dd_data = {"dd-pathway-ctx-base64": "12345"}
        dd_json_data = json.dumps(dd_data)
        encoded_data = base64.b64encode(dd_json_data.encode()).decode()

        event = {
            "Records": [
                {
                    "eventSourceARN": "",
                    "Sns": {
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                        "MessageAttributes": {
                            "_datadog": {"Type": "Binary", "Value": encoded_data}
                        },
                    },
                    "eventSource": "aws:sns",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sns")
        self.assertEqual(args[1], "arn:aws:sns:us-east-1:123456789012:test-topic")
        carrier_get = args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

    def test_sns_no_datadog_message_attribute(self):
        event = {
            "Records": [
                {
                    "Sns": {
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                        "MessageAttributes": {},  # No _datadog key
                    },
                    "eventSource": "aws:sns",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )
        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sns")
        self.assertEqual(args[1], "arn:aws:sns:us-east-1:123456789012:test-topic")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_sns_empty_datadog_message_attribute(self):
        event = {
            "Records": [
                {
                    "Sns": {
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                        "MessageAttributes": {
                            "_datadog": {
                                "Type": "String",
                                "Value": "null",
                            }  # json.loads("null") => None
                        },
                    },
                    "eventSource": "aws:sns",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )
        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sns")
        self.assertEqual(args[1], "arn:aws:sns:us-east-1:123456789012:test-topic")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_sns_no_DSM_context_in_message_attribute(self):
        dd_data = {"NOT-DSM-KEY": "12345"}
        dd_json_data = json.dumps(dd_data)

        event = {
            "Records": [
                {
                    "eventSourceARN": "",
                    "Sns": {
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                        "MessageAttributes": {
                            "_datadog": {"Type": "String", "Value": dd_json_data}
                        },
                    },
                    "eventSource": "aws:sns",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sns")
        self.assertEqual(args[1], "arn:aws:sns:us-east-1:123456789012:test-topic")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    @patch("datadog_lambda.tracing.logger")
    def test_sns_invalid_datadog_message_attribute(self, mock_logger):
        test_cases = [
            {
                "name": "invalid_base64",
                "event": {
                    "Records": [
                        {
                            "Sns": {
                                "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                                "MessageAttributes": {
                                    "_datadog": {
                                        "Type": "Binary",
                                        "Value": "invalid-base64",
                                    }
                                },
                            },
                            "eventSource": "aws:sns",
                        }
                    ]
                },
                "expected_log": ("The trace extractor returned with error %s", ANY),
            },
            {
                "name": "unsupported_datatype",
                "event": {
                    "Records": [
                        {
                            "Sns": {
                                "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                                "MessageAttributes": {
                                    "_datadog": {
                                        "Type": "Number",
                                        "numberValue": 123,
                                    }  # Unsupported type
                                },
                            },
                            "eventSource": "aws:sns",
                        }
                    ]
                },
                "expected_log": (
                    "Datadog Lambda Python only supports extracting trace"
                    "context from String or Binary SQS/SNS message attributes",
                ),
            },
        ]

        for test_case in test_cases:
            with self.subTest(test_case=test_case["name"]):
                mock_logger.reset_mock()
                self.mock_checkpoint.reset_mock()

                extract_context_from_sqs_or_sns_event_or_context(
                    test_case["event"],
                    self.lambda_context,
                    parse_event_source(test_case["event"]),
                )

                # Exception triggers logger
                mock_logger.debug.assert_any_call(*test_case["expected_log"])

                self.assertEqual(self.mock_checkpoint.call_count, 1)
                args, _ = self.mock_checkpoint.call_args
                self.assertEqual(args[0], "sns")
                self.assertEqual(
                    args[1], "arn:aws:sns:us-east-1:123456789012:test-topic"
                )
                carrier_get = args[2]
                # None indicates no DSM context propagation
                self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_sns_source_arn_not_found(self):
        event = {
            "Records": [
                {
                    "Sns": {
                        "TopicArn": "",
                        "MessageAttributes": {},
                    },
                    "eventSource": "aws:sns",
                    "eventSourceARN": "",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )

        self.mock_checkpoint.assert_not_called()

    @patch("datadog_lambda.config.Config.data_streams_enabled", False)
    def test_sns_data_streams_disabled(self):
        context_json = {"dd-pathway-ctx-base64": "12345"}
        event_type = "sns"
        arn = "arn:aws:sns:us-east-1:123456789012:test-topic"

        _dsm_set_checkpoint(context_json, event_type, arn)

        self.mock_checkpoint.assert_not_called()

    # SNS -> SQS TESTS

    def test_sns_to_sqs_context_propagated_string_value(self):
        dd_data = {"dd-pathway-ctx-base64": "12345"}
        dd_json_data = json.dumps(dd_data)

        sns_notification = {
            "Type": "Notification",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
            "MessageAttributes": {
                "_datadog": {"Type": "String", "Value": dd_json_data}
            },
            "Message": "test message",
        }

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "body": json.dumps(sns_notification),
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        # Should use SQS ARN, not SNS ARN
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

    def test_sns_to_sqs_context_propagated_binary_value(self):
        dd_data = {"dd-pathway-ctx-base64": "12345"}
        dd_json_data = json.dumps(dd_data)
        encoded_data = base64.b64encode(dd_json_data.encode()).decode()

        sns_notification = {
            "Type": "Notification",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
            "MessageAttributes": {
                "_datadog": {"Type": "Binary", "Value": encoded_data}
            },
            "Message": "test message",
        }

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "body": json.dumps(sns_notification),
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )
        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        # Should use SQS ARN, not SNS ARN
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

    def test_sns_to_sqs_no_datadog_message_attribute(self):
        sns_notification = {
            "Type": "Notification",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
            "MessageAttributes": {},  # No _datadog key
            "Message": "test message",
        }

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "body": json.dumps(sns_notification),
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )
        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        # Should use SQS ARN, not SNS ARN
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_sns_to_sqs_empty_datadog_message_attribute(self):
        sns_notification = {
            "Type": "Notification",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
            "MessageAttributes": {
                "_datadog": {
                    "Type": "String",
                    "Value": "null",
                }  # json.loads("null") => None
            },
            "Message": "test message",
        }

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "body": json.dumps(sns_notification),
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )
        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        # Should use SQS ARN, not SNS ARN
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_sns_to_sqs_no_DSM_context_in_message_attribute(self):
        dd_data = {"NOT-DSM-KEY": "12345"}
        dd_json_data = json.dumps(dd_data)
        encoded_data = base64.b64encode(dd_json_data.encode()).decode()

        sns_notification = {
            "Type": "Notification",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
            "MessageAttributes": {
                "_datadog": {"Type": "Binary", "Value": encoded_data}
            },
            "Message": "test message",
        }

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "body": json.dumps(sns_notification),
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        # Should use SQS ARN, not SNS ARN
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    @patch("datadog_lambda.tracing.logger")
    def test_sns_to_sqs_invalid_datadog_message_attribute(self, mock_logger):
        test_cases = [
            {
                "name": "invalid_base64",
                "sns_notification": {
                    "Type": "Notification",
                    "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                    "MessageAttributes": {
                        "_datadog": {"Type": "Binary", "Value": "not-base64"}
                    },
                    "Message": "test message",
                },
                "expected_log": ("The trace extractor returned with error %s", ANY),
            },
            {
                "name": "unsupported_datatype",
                "sns_notification": {
                    "Type": "Notification",
                    "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                    "MessageAttributes": {
                        "_datadog": {
                            "Type": "Number",
                            "numberValue": 123,
                        }  # Unsupported type
                    },
                    "Message": "test message",
                },
                "expected_log": (
                    "Datadog Lambda Python only supports extracting trace"
                    "context from String or Binary SQS/SNS message attributes",
                ),
            },
        ]

        for test_case in test_cases:
            with self.subTest(test_case=test_case["name"]):
                mock_logger.reset_mock()
                self.mock_checkpoint.reset_mock()

                event = {
                    "Records": [
                        {
                            "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                            "body": json.dumps(test_case["sns_notification"]),
                            "eventSource": "aws:sqs",
                        }
                    ]
                }

                extract_context_from_sqs_or_sns_event_or_context(
                    event, self.lambda_context, parse_event_source(event)
                )

                # Exception triggers logger
                mock_logger.debug.assert_any_call(*test_case["expected_log"])

                self.assertEqual(self.mock_checkpoint.call_count, 1)
                args, _ = self.mock_checkpoint.call_args
                self.assertEqual(args[0], "sqs")
                # Should use SQS ARN, not SNS ARN
                self.assertEqual(
                    args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue"
                )
                carrier_get = args[2]
                # None indicates no DSM context propagation
                self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_sns_to_sqs_source_arn_not_found(self):
        sns_notification = {
            "Type": "Notification",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
            "MessageAttributes": {},
            "Message": "test message",
        }

        event = {
            "Records": [
                {
                    "eventSourceARN": "",  # Empty SQS ARN
                    "body": json.dumps(sns_notification),
                    "eventSource": "aws:sqs",
                }
            ]
        }

        extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context, parse_event_source(event)
        )

        self.mock_checkpoint.assert_not_called()

    @patch("datadog_lambda.config.Config.data_streams_enabled", False)
    def test_sns_to_sqs_data_streams_disabled(self):
        context_json = {"dd-pathway-ctx-base64": "12345"}
        event_type = "sqs"
        arn = "arn:aws:sqs:us-east-1:123456789012:test-queue"

        _dsm_set_checkpoint(context_json, event_type, arn)

        self.mock_checkpoint.assert_not_called()

    # KINESIS TESTS

    def test_kinesis_context_propagated_binary_value(self):
        dd_data = {"dd-pathway-ctx-base64": "12345"}
        kinesis_data = {"_datadog": dd_data, "message": "test"}
        kinesis_data_str = json.dumps(kinesis_data)
        encoded_data = base64.b64encode(kinesis_data_str.encode()).decode()

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream",
                    "kinesis": {"data": encoded_data},
                }
            ]
        }

        extract_context_from_kinesis_event(event, self.lambda_context)

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "kinesis")
        self.assertEqual(
            args[1], "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream"
        )
        carrier_get = args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

    def test_kinesis_no_datadog_message_attribute(self):
        kinesis_data = {"message": "test"}  # No _datadog key
        kinesis_data_str = json.dumps(kinesis_data)
        encoded_data = base64.b64encode(kinesis_data_str.encode()).decode()

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream",
                    "kinesis": {"data": encoded_data},
                }
            ]
        }

        extract_context_from_kinesis_event(event, self.lambda_context)

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "kinesis")
        self.assertEqual(
            args[1], "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream"
        )
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_kinesis_empty_message_attribute(self):
        kinesis_data = {"_datadog": None, "message": "test"}  # _datadog is None
        kinesis_data_str = json.dumps(kinesis_data)
        encoded_data = base64.b64encode(kinesis_data_str.encode()).decode()

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream",
                    "kinesis": {"data": encoded_data},
                }
            ]
        }

        extract_context_from_kinesis_event(event, self.lambda_context)
        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "kinesis")
        self.assertEqual(
            args[1], "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream"
        )
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_kinesis_no_DSM_context_in_message_attribute(self):
        dd_data = {"NOT-DSM-KEY": "12345"}
        kinesis_data = {"_datadog": dd_data, "message": "test"}
        kinesis_data_str = json.dumps(kinesis_data)
        encoded_data = base64.b64encode(kinesis_data_str.encode()).decode()

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream",
                    "kinesis": {"data": encoded_data},
                }
            ]
        }

        extract_context_from_kinesis_event(event, self.lambda_context)

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "kinesis")
        self.assertEqual(
            args[1], "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream"
        )
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    @patch("datadog_lambda.tracing.logger")
    def test_kinesis_invalid_datadog_message_attribute(self, mock_logger):
        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream",
                    "kinesis": {"data": "invalid-base64"},
                }
            ]
        }

        extract_context_from_kinesis_event(event, self.lambda_context)
        # Exception triggers logger
        mock_logger.debug.assert_any_call(
            "The trace extractor returned with error %s",
            ANY,
        )
        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "kinesis")
        self.assertEqual(
            args[1], "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream"
        )
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    def test_kinesis_source_arn_not_found(self):
        kinesis_data = {"message": "test"}
        kinesis_data_str = json.dumps(kinesis_data)
        encoded_data = base64.b64encode(kinesis_data_str.encode()).decode()

        event = {
            "Records": [
                {
                    "eventSourceARN": "",
                    "kinesis": {"data": encoded_data},
                }
            ]
        }

        extract_context_from_kinesis_event(event, self.lambda_context)

        self.mock_checkpoint.assert_not_called()

    @patch("datadog_lambda.config.Config.data_streams_enabled", False)
    def test_kinesis_data_streams_disabled(self):
        context_json = {"dd-pathway-ctx-base64": "12345"}
        event_type = "kinesis"
        arn = "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream"

        _dsm_set_checkpoint(context_json, event_type, arn)
