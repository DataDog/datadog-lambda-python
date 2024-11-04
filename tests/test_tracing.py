import copy
import functools
import json
import traceback
import pytest
import os
import unittest

from unittest.mock import Mock, patch, call

import ddtrace

from ddtrace import tracer
from ddtrace.context import Context
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
    InferredSpanInfo,
    create_service_mapping,
    determine_service_name,
    service_mapping as global_service_mapping,
    propagator,
    emit_telemetry_on_exception_outside_of_handler,
    is_legacy_lambda_step_function,
)
from datadog_lambda.trigger import EventTypes

from tests.utils import get_mock_context


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

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data(self):
        lambda_ctx = get_mock_context()
        sf_event = {
            "Execution": {
                "Id": "665c417c-1237-4742-aaca-8b3becbb9e75",
            },
            "StateMachine": {},
            "State": {
                "Name": "my-awesome-state",
                "EnteredTime": "Mon Nov 13 12:43:33 PST 2023",
            },
        }
        ctx, source, event_source = extract_dd_trace_context(sf_event, lambda_ctx)
        self.assertEqual(source, "event")
        expected_context = Context(
            trace_id=3675572987363469717,
            span_id=6880978411788117524,
            sampling_priority=1,
            meta={"_dd.p.tid": "e987c84b36b11ab"},
        )
        self.assertEqual(ctx, expected_context)
        self.assertEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "3675572987363469717",
                TraceHeader.PARENT_ID: "10713633173203262661",
                TraceHeader.SAMPLING_PRIORITY: "1",
                TraceHeader.TAGS: "_dd.p.tid=e987c84b36b11ab",
            },
        )
        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_send_segment.assert_called_with(
            XraySubsegment.TRACE_KEY,
            expected_context,
        )

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data_with_trace_header(self):
        lambda_ctx = get_mock_context()
        sf_event = {
            "Execution": {
                "Id": "665c417c-1237-4742-aaca-8b3becbb9e75",
            },
            "StateMachine": {},
            "State": {
                "Name": "my-awesome-state",
                "EnteredTime": "Mon Nov 13 12:43:33 PST 2023",
            },
            "_datadog": {
                "x-datadog-trace-id": "11742251842529032210",
                "x-datadog-parent-id": "13977111940858727778",
                "x-datadog-sampling-priority": "1",
                "x-datadog-tags": "_dd.p.dm=-0,_dd.p.tid=6728f8ec00000000"
            },
        }
        ctx, source, event_source = extract_dd_trace_context(sf_event, lambda_ctx)
        self.assertEqual(source, "event")
        expected_context = Context(
            trace_id=137123224175615787006624409899264538642,
            span_id=6880978411788117524,
            sampling_priority=1,
            meta={'_dd.p.dm': '-0', "_dd.p.tid": "6728f8ec00000000"},
        )
        self.assertEqual(ctx, expected_context)
        self.assertEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "11742251842529032210",
                TraceHeader.PARENT_ID: "10713633173203262661",
                TraceHeader.SAMPLING_PRIORITY: "1",
                TraceHeader.TAGS: "_dd.p.dm=-0,_dd.p.tid=6728f8ec00000000",
            },
        )
        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_send_segment.assert_called_with(
            XraySubsegment.TRACE_KEY,
            expected_context,
        )

    @with_trace_propagation_style("datadog")
    def test_step_function_trace_data_with_arn_header(self):
        lambda_ctx = get_mock_context()
        sf_event = {
            "Execution": {
                "Id": "665c417c-1237-4742-aaca-8b3becbb9e75",
            },
            "StateMachine": {},
            "State": {
                "Name": "my-awesome-state",
                "EnteredTime": "Mon Nov 13 12:43:33 PST 2023",
            },
            "_datadog": {
                "x-datadog-root-execution-arn": "ca7383bc-e370-4a85-a266-a4686bd7d00f"
            },
        }
        ctx, source, event_source = extract_dd_trace_context(sf_event, lambda_ctx)
        self.assertEqual(source, "event")
        expected_context = Context(
            trace_id=3675572987363469717,
            span_id=6880978411788117524,
            sampling_priority=1,
            meta={"_dd.p.tid": "e987c84b36b11ab"},
        )
        self.assertEqual(ctx, expected_context)
        self.assertEqual(
            get_dd_trace_context(),
            {
                TraceHeader.TRACE_ID: "3675572987363469717",
                TraceHeader.PARENT_ID: "10713633173203262661",
                TraceHeader.SAMPLING_PRIORITY: "1",
                TraceHeader.TAGS: "_dd.p.tid=e987c84b36b11ab",
            },
        )
        create_dd_dummy_metadata_subsegment(ctx, XraySubsegment.TRACE_KEY)
        self.mock_send_segment.assert_called_with(
            XraySubsegment.TRACE_KEY,
            expected_context,
        )

    def test_is_legacy_lambda_step_function(self):
        sf_event = {
            "Payload": {
                "Execution": {
                    "Id": "665c417c-1237-4742-aaca-8b3becbb9e75",
                },
                "StateMachine": {},
                "State": {
                    "Name": "my-awesome-state",
                    "EnteredTime": "Mon Nov 13 12:43:33 PST 2023",
                },
            }
        }
        self.assertTrue(is_legacy_lambda_step_function(sf_event))

        sf_event = {
            "Execution": {
                "Id": "665c417c-1237-4742-aaca-8b3becbb9e75",
            },
            "StateMachine": {},
            "State": {
                "Name": "my-awesome-state",
                "EnteredTime": "Mon Nov 13 12:43:33 PST 2023",
            },
        }
        self.assertFalse(is_legacy_lambda_step_function(sf_event))


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

        patcher = patch("datadog_lambda.tracing.is_lambda_context")
        self.mock_is_lambda_context = patcher.start()
        self.mock_is_lambda_context.return_value = True
        self.addCleanup(patcher.stop)

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
        patcher = patch("datadog_lambda.tracing.tracer.context_provider.activate")
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
        self.assertEqual(span1.get_tag("operation_name"), "aws.apigateway.rest")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["requestContext"][
            "domainName"
        ] = "different.execute-api.us-east-2.amazonaws.com"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.apigateway.rest")
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
        self.assertEqual(span1.get_tag("operation_name"), "aws.apigateway.rest")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["requestContext"]["apiId"] = "different"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.apigateway.rest")
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
        self.assertEqual(span1.get_tag("operation_name"), "aws.httpapi")
        self.assertEqual(span1.service, "new-name")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["requestContext"]["apiId"] = "different"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.httpapi")
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
        self.assertEqual(span2.service, "sqs")

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
        self.assertEqual(span2.service, "sns")

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
        self.assertEqual(span1.service, "kinesis")

        # Testing the second event
        event2 = copy.deepcopy(original_event)
        event2["Records"][0][
            "eventSourceARN"
        ] = "arn:aws:kinesis:eu-west-1:601427279990:stream/DifferentKinesisStream"
        span2 = create_inferred_span(event2, ctx)
        self.assertEqual(span2.get_tag("operation_name"), "aws.kinesis")
        self.assertEqual(span2.service, "kinesis")

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
        self.assertEqual(span2.service, "s3")

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
        self.assertEqual(span2.service, "dynamodb")

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
        self.assertEqual(span2.service, "eventbridge")


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
            span_type="http",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "1234567890",
                "apiname": "1234567890",
                "endpoint": "/path/to/resource",
                "http.method": "POST",
                "http.url": "70ixmpl4fl.execute-api.us-east-2.amazonaws.com/path/to/resource",
                "operation_name": "aws.apigateway.rest",
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
            span_type="http",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "async",
                "_inferred_span.tag_source": "self",
                "apiid": "lgxbo6a518",
                "apiname": "lgxbo6a518",
                "endpoint": "/http/get",
                "http.method": "GET",
                "http.url": "lgxbo6a518.execute-api.eu-west-1.amazonaws.com/http/get",
                "operation_name": "aws.apigateway.rest",
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
            span_type="http",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "lgxbo6a518",
                "apiname": "lgxbo6a518",
                "endpoint": "/http/get",
                "http.method": "GET",
                "http.url": "lgxbo6a518.execute-api.eu-west-1.amazonaws.com/http/get",
                "operation_name": "aws.apigateway.rest",
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
            span_type="http",
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
                "http.url": "x02yirxc7a.execute-api.eu-west-1.amazonaws.com/httpapi/get",
                "http.user_agent": "curl/7.64.1",
                "operation_name": "aws.httpapi",
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
            span_type="http",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "mcwkra0ya4",
                "apiname": "mcwkra0ya4",
                "endpoint": "/user/42",
                "http.method": "GET",
                "http.url": "mcwkra0ya4.execute-api.sa-east-1.amazonaws.com/user/42",
                "operation_name": "aws.apigateway.rest",
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
            span_type="http",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "9vj54we5ih",
                "apiname": "9vj54we5ih",
                "endpoint": "/user/42",
                "http.method": "GET",
                "http.url": "9vj54we5ih.execute-api.sa-east-1.amazonaws.com/user/42",
                "operation_name": "aws.httpapi",
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
                "http.url": "p62c47itsb.execute-api.eu-west-1.amazonaws.com$default",
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
                "http.url": "p62c47itsb.execute-api.eu-west-1.amazonaws.com$connect",
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
                "http.url": "p62c47itsb.execute-api.eu-west-1.amazonaws.com$disconnect",
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
            service="sqs",
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
            service="sns",
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
            service="sns",
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
        "kinesis",
        _Span(
            service="kinesis",
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
                "resource_names": "stream/kinesisStream",
                "shardid": "shardId-000000000002",
                "streamname": "stream/kinesisStream",
            },
        ),
    ),
    (
        "dynamodb",
        _Span(
            service="dynamodb",
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
            service="s3",
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
            service="eventbridge",
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
            service="sqs",
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
            span_type="http",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "None",
                "apiname": "None",
                "endpoint": "/path/to/resource",
                "http.method": "POST",
                "http.url": "70ixmpl4fl.execute-api.us-east-2.amazonaws.com/path/to/resource",
                "operation_name": "aws.apigateway.rest",
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
            span_type="http",
            parent_name="aws.apigateway.authorizer",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "operation_name": "aws.apigateway.rest",
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
            span_type="http",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "operation_name": "aws.apigateway.rest",
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
            span_type="http",
            parent_name="aws.apigateway.authorizer",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "operation_name": "aws.apigateway.rest",
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
            span_type="http",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "operation_name": "aws.apigateway.rest",
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
            span_type="http",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "operation_name": "aws.httpapi",
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
            span_type="http",
            tags={
                "_dd.origin": "lambda",
                "_inferred_span.synchronicity": "sync",
                "_inferred_span.tag_source": "self",
                "apiid": "amddr1rix9",
                "apiname": "amddr1rix9",
                "endpoint": "/hello",
                "http.method": "GET",
                "http.url": "amddr1rix9.execute-api.eu-west-1.amazonaws.com/hello",
                "operation_name": "aws.httpapi",
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
                "http.url": "amddr1rix9.execute-api.eu-west-1.amazonaws.com$connect",
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
                "http.url": "amddr1rix9.execute-api.eu-west-1.amazonaws.commain",
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
@patch("ddtrace.Span.finish", autospec=True)
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
        mock_span = Mock(ddtrace.Span)
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
    @patch("datadog_lambda.tracing.dd_tracing_enabled", True)
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

    @patch("datadog_lambda.tracing.dd_tracing_enabled", False)
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
