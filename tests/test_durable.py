# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.
import unittest

from datadog_lambda.durable import (
    _parse_durable_execution_arn,
    extract_durable_function_tags,
    extract_durable_execution_status,
)


class TestParseDurableExecutionArn(unittest.TestCase):
    def test_returns_name_and_id_for_valid_arn(self):
        arn = "arn:aws:lambda:us-east-1:123456789012:function:my-func:$LATEST/durable-execution/order-123/550e8400-e29b-41d4-a716-446655440001"
        result = _parse_durable_execution_arn(arn)
        self.assertEqual(result, ("order-123", "550e8400-e29b-41d4-a716-446655440001"))

    def test_returns_none_for_arn_without_durable_execution_marker(self):
        arn = "arn:aws:lambda:us-east-1:123456789012:function:my-func:$LATEST"
        result = _parse_durable_execution_arn(arn)
        self.assertIsNone(result)

    def test_returns_none_for_malformed_arn_with_only_execution_name(self):
        arn = "arn:aws:lambda:us-east-1:123456789012:function:my-func:$LATEST/durable-execution/order-123"
        result = _parse_durable_execution_arn(arn)
        self.assertIsNone(result)

    def test_returns_none_for_malformed_arn_with_empty_execution_name(self):
        arn = "arn:aws:lambda:us-east-1:123456789012:function:my-func:$LATEST/durable-execution//550e8400-e29b-41d4-a716-446655440002"
        result = _parse_durable_execution_arn(arn)
        self.assertIsNone(result)

    def test_returns_none_for_malformed_arn_with_empty_execution_id(self):
        arn = "arn:aws:lambda:us-east-1:123456789012:function:my-func:$LATEST/durable-execution/order-123/"
        result = _parse_durable_execution_arn(arn)
        self.assertIsNone(result)

    def test_works_with_numeric_version_qualifier(self):
        arn = "arn:aws:lambda:us-east-1:123456789012:function:my-func:1/durable-execution/my-execution/550e8400-e29b-41d4-a716-446655440004"
        result = _parse_durable_execution_arn(arn)
        self.assertEqual(
            result, ("my-execution", "550e8400-e29b-41d4-a716-446655440004")
        )


class TestExtractDurableFunctionTags(unittest.TestCase):
    def test_sets_first_invocation_true_when_only_execution_operation(self):
        # One operation (the current EXECUTION operation itself) → not replaying → first invocation
        event = {
            "DurableExecutionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-func:1/durable-execution/my-execution/550e8400-e29b-41d4-a716-446655440004",
            "CheckpointToken": "some-token",
            "InitialExecutionState": {"Operations": [{"OperationType": "EXECUTION"}]},
        }
        result = extract_durable_function_tags(event)
        self.assertEqual(
            result,
            {
                "aws_lambda.durable_function.execution_name": "my-execution",
                "aws_lambda.durable_function.execution_id": "550e8400-e29b-41d4-a716-446655440004",
                "aws_lambda.durable_function.first_invocation": "true",
            },
        )

    def test_sets_first_invocation_false_when_multiple_operations(self):
        # More than one operation → replaying → not first invocation
        event = {
            "DurableExecutionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-func:1/durable-execution/my-execution/550e8400-e29b-41d4-a716-446655440004",
            "CheckpointToken": "some-token",
            "InitialExecutionState": {
                "Operations": [
                    {"OperationType": "EXECUTION"},
                    {"OperationType": "STEP"},
                ]
            },
        }
        result = extract_durable_function_tags(event)
        self.assertEqual(
            result,
            {
                "aws_lambda.durable_function.execution_name": "my-execution",
                "aws_lambda.durable_function.execution_id": "550e8400-e29b-41d4-a716-446655440004",
                "aws_lambda.durable_function.first_invocation": "false",
            },
        )

    def test_returns_empty_dict_for_regular_lambda_event(self):
        event = {
            "body": '{"key": "value"}',
            "headers": {"Content-Type": "application/json"},
        }
        result = extract_durable_function_tags(event)
        self.assertEqual(result, {})

    def test_returns_empty_dict_when_event_is_none(self):
        result = extract_durable_function_tags(None)
        self.assertEqual(result, {})

    def test_returns_empty_dict_when_event_is_not_a_dict(self):
        result = extract_durable_function_tags("not-a-dict")
        self.assertEqual(result, {})

    def test_returns_empty_dict_when_durable_execution_arn_is_not_a_string(self):
        event = {"DurableExecutionArn": 12345}
        result = extract_durable_function_tags(event)
        self.assertEqual(result, {})

    def test_returns_empty_dict_when_durable_execution_arn_cannot_be_parsed(self):
        event = {"DurableExecutionArn": "invalid-arn-without-durable-execution-marker"}
        result = extract_durable_function_tags(event)
        self.assertEqual(result, {})

    def test_returns_empty_dict_when_event_is_empty(self):
        result = extract_durable_function_tags({})
        self.assertEqual(result, {})


class TestExtractDurableExecutionStatus(unittest.TestCase):
    def test_returns_succeeded(self):
        event = {
            "DurableExecutionArn": "arn:aws:lambda:us-east-1:123:function:f:1/durable-execution/n/id"
        }
        response = {"Status": "SUCCEEDED", "Result": "some-result"}
        self.assertEqual(extract_durable_execution_status(response, event), "SUCCEEDED")

    def test_returns_failed(self):
        event = {
            "DurableExecutionArn": "arn:aws:lambda:us-east-1:123:function:f:1/durable-execution/n/id"
        }
        response = {"Status": "FAILED", "Error": "some-error"}
        self.assertEqual(extract_durable_execution_status(response, event), "FAILED")

    def test_returns_pending(self):
        event = {
            "DurableExecutionArn": "arn:aws:lambda:us-east-1:123:function:f:1/durable-execution/n/id"
        }
        response = {"Status": "PENDING"}
        self.assertEqual(extract_durable_execution_status(response, event), "PENDING")

    def test_returns_none_for_non_durable_event(self):
        event = {"key": "value"}
        response = {"Status": "SUCCEEDED"}
        self.assertIsNone(extract_durable_execution_status(response, event))

    def test_returns_none_for_non_dict_response(self):
        event = {
            "DurableExecutionArn": "arn:aws:lambda:us-east-1:123:function:f:1/durable-execution/n/id"
        }
        self.assertIsNone(extract_durable_execution_status("string", event))

    def test_returns_none_for_missing_status(self):
        event = {
            "DurableExecutionArn": "arn:aws:lambda:us-east-1:123:function:f:1/durable-execution/n/id"
        }
        response = {"Result": "some-result"}
        self.assertIsNone(extract_durable_execution_status(response, event))

    def test_returns_none_for_invalid_status(self):
        event = {
            "DurableExecutionArn": "arn:aws:lambda:us-east-1:123:function:f:1/durable-execution/n/id"
        }
        response = {"Status": "INVALID"}
        self.assertIsNone(extract_durable_execution_status(response, event))

    def test_returns_none_for_non_dict_event(self):
        response = {"Status": "SUCCEEDED"}
        self.assertIsNone(extract_durable_execution_status(response, "not-a-dict"))

    def test_returns_none_for_none_event(self):
        response = {"Status": "SUCCEEDED"}
        self.assertIsNone(extract_durable_execution_status(response, None))

    def test_returns_none_for_none_response(self):
        event = {
            "DurableExecutionArn": "arn:aws:lambda:us-east-1:123:function:f:1/durable-execution/n/id"
        }
        self.assertIsNone(extract_durable_execution_status(None, event))


import json

from datadog_lambda.tracing import (
    create_durable_execution_root_span,
    extract_context_from_durable_execution,
    is_durable_execution_replay,
)


_TEST_ARN = "arn:aws:lambda:us-east-2:1:function:f:1" "/durable-execution/wf/abc-123"


def _event(operations):
    return {
        "DurableExecutionArn": _TEST_ARN,
        "InitialExecutionState": {"Operations": operations},
    }


def _execution_op(input_payload=None):
    op = {"OperationType": "EXECUTION", "Name": "execution"}
    if input_payload is not None:
        op["ExecutionDetails"] = {"InputPayload": input_payload}
    return op


def _trace_checkpoint_op(n, headers):
    return {
        "OperationType": "STEP",
        "Id": f"id-{n}",
        "Name": f"_datadog_{n}",
        "StepDetails": {"Result": json.dumps(headers)},
    }


class TestExtractContextPriorityOne(unittest.TestCase):
    """Highest-numbered ``_datadog_{N}`` STEP wins."""

    def test_returns_context_from_latest_checkpoint(self):
        ev = _event(
            [
                _execution_op(),
                _trace_checkpoint_op(
                    0,
                    {
                        "x-datadog-trace-id": "111",
                        "x-datadog-parent-id": "222",
                        "x-datadog-sampling-priority": "1",
                    },
                ),
                _trace_checkpoint_op(
                    1,
                    {
                        "x-datadog-trace-id": "111",
                        "x-datadog-parent-id": "333",
                        "x-datadog-sampling-priority": "1",
                    },
                ),
            ]
        )
        ctx = extract_context_from_durable_execution(ev, None)
        self.assertEqual(ctx.trace_id, 111)
        # Latest checkpoint (N=1) wins.
        self.assertEqual(ctx.span_id, 333)


class TestExtractContextPriorityTwo(unittest.TestCase):
    """When no checkpoint exists, fall back to the original event payload."""

    def test_extracts_from_input_payload_headers_field(self):
        upstream_headers = {
            "x-datadog-trace-id": "777",
            "x-datadog-parent-id": "888",
            "x-datadog-sampling-priority": "1",
        }
        input_payload = json.dumps({"headers": upstream_headers, "body": "..."})
        ev = _event([_execution_op(input_payload)])
        ctx = extract_context_from_durable_execution(ev, None)
        self.assertEqual(ctx.trace_id, 777)
        self.assertEqual(ctx.span_id, 888)

    def test_extracts_from_input_payload_underscore_datadog_field(self):
        upstream_headers = {
            "x-datadog-trace-id": "999",
            "x-datadog-parent-id": "111",
            "x-datadog-sampling-priority": "1",
        }
        input_payload = json.dumps({"_datadog": upstream_headers})
        ev = _event([_execution_op(input_payload)])
        ctx = extract_context_from_durable_execution(ev, None)
        self.assertEqual(ctx.trace_id, 999)


class TestExtractContextReturnsNoneWhenNoUpstream(unittest.TestCase):
    """No checkpoint and no upstream headers → return None and let the rest
    of the extraction chain run. The tracer mints a fresh trace on the first
    invocation; subsequent invocations recover it via the priority-1 checkpoint.
    """

    def test_returns_none_when_only_execution_op(self):
        ev = _event([_execution_op()])
        self.assertIsNone(extract_context_from_durable_execution(ev, None))

    def test_returns_none_when_input_payload_has_no_dd_headers(self):
        ev = _event([_execution_op(json.dumps({"some": "user-event"}))])
        self.assertIsNone(extract_context_from_durable_execution(ev, None))


class TestIsDurableExecutionReplay(unittest.TestCase):
    def test_first_invocation_is_not_replay(self):
        self.assertFalse(is_durable_execution_replay(_event([_execution_op()])))

    def test_second_invocation_is_replay(self):
        ev = _event([_execution_op(), _trace_checkpoint_op(0, {})])
        self.assertTrue(is_durable_execution_replay(ev))

    def test_non_durable_event_is_not_replay(self):
        self.assertFalse(is_durable_execution_replay({"body": "..."}))


class TestCreateDurableExecutionRootSpan(unittest.TestCase):
    def test_returns_none_on_replay(self):
        ev = _event([_execution_op(), _trace_checkpoint_op(0, {})])
        self.assertIsNone(create_durable_execution_root_span(ev))

    def test_returns_none_for_non_durable_event(self):
        self.assertIsNone(create_durable_execution_root_span({"body": "..."}))

    def test_first_invocation_returns_a_span(self):
        ev = _event([_execution_op()])
        span = create_durable_execution_root_span(ev)
        try:
            self.assertIsNotNone(span)
            # The span_id is whatever the tracer minted; dd-trace-py reads it
            # back via a grandparent walk from the in-process span tree, so we
            # don't assert any deterministic relationship to the ARN here.
            self.assertGreater(span.span_id, 0)
            self.assertEqual(span.get_tag("durable.execution_arn"), _TEST_ARN)
        finally:
            if span is not None:
                span.finish()
