# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.
import unittest

from datadog_lambda.durable import (
    _parse_durable_execution_arn,
    extract_durable_function_tags,
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
        self.assertEqual(result, ("my-execution", "550e8400-e29b-41d4-a716-446655440004"))


class TestExtractDurableFunctionTags(unittest.TestCase):
    def test_extracts_tags_from_event_with_durable_execution_arn(self):
        event = {
            "DurableExecutionArn": "arn:aws:lambda:us-east-1:123456789012:function:my-func:1/durable-execution/my-execution/550e8400-e29b-41d4-a716-446655440004",
            "CheckpointToken": "some-token",
            "InitialExecutionState": {"Operations": []},
        }
        result = extract_durable_function_tags(event)
        self.assertEqual(
            result,
            {
                "durable_function_execution_name": "my-execution",
                "durable_function_execution_id": "550e8400-e29b-41d4-a716-446655440004",
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
