import json
import unittest
import base64
import os
from unittest.mock import patch

from ddtrace.trace import Context

from datadog_lambda.tracing import (
    _extract_context_with_data_streams,
    _create_carrier_get,
    extract_context_from_sqs_or_sns_event_or_context,
    extract_context_from_kinesis_event,
)
from tests.utils import get_mock_context


class TestExtractContext(unittest.TestCase):
    def setUp(self):
        patcher = patch("datadog_lambda.tracing.propagator.extract")
        self.mock_extract = patcher.start()
        self.addCleanup(patcher.stop)

        checkpoint_patcher = patch("ddtrace.data_streams.set_consume_checkpoint")
        self.mock_checkpoint = checkpoint_patcher.start()
        self.addCleanup(checkpoint_patcher.stop)

        logger_patcher = patch("datadog_lambda.tracing.logger")
        self.mock_logger = logger_patcher.start()
        self.addCleanup(logger_patcher.stop)

    def test_extract_context_data_streams_disabled(self):
        with patch.dict(os.environ, {"DD_DATA_STREAMS_ENABLED": "false"}):
            context_json = {"dd-pathway-ctx-base64": "12345"}
            event_type = "sqs"
            arn = "arn:aws:sqs:us-east-1:123456789012:test-queue"

            mock_context = Context(trace_id=12345, span_id=67890, sampling_priority=1)
            self.mock_extract.return_value = mock_context

            result = _extract_context_with_data_streams(context_json, event_type, arn)

            self.mock_extract.assert_called_once_with(context_json)
            self.mock_checkpoint.assert_not_called()
            self.assertEqual(result, mock_context)

    def test_extract_context_data_streams_enabled_complete_context(self):
        with patch.dict(os.environ, {"DD_DATA_STREAMS_ENABLED": "true"}):
            context_json = {"dd-pathway-ctx-base64": "12345"}
            event_type = "sqs"
            arn = "arn:aws:sqs:us-east-1:123456789012:test-queue"

            mock_context = Context(trace_id=12345, span_id=67890, sampling_priority=1)
            self.mock_extract.return_value = mock_context

            result = _extract_context_with_data_streams(context_json, event_type, arn)

            self.mock_extract.assert_called_once_with(context_json)
            self.mock_checkpoint.assert_called_once()
            args, kwargs = self.mock_checkpoint.call_args
            self.assertEqual(args[0], event_type)
            self.assertEqual(args[1], arn)
            self.assertTrue(callable(args[2]))
            self.assertEqual(kwargs["manual_checkpoint"], False)
            self.assertEqual(result, mock_context)

    def test_extract_context_data_streams_enabled_incomplete_context(self):
        with patch.dict(os.environ, {"DD_DATA_STREAMS_ENABLED": "true"}):
            context_json = {"dd-pathway-ctx-base64": "12345"}
            event_type = "sqs"
            arn = "arn:aws:sqs:us-east-1:123456789012:test-queue"

            mock_context = Context(trace_id=12345, span_id=None, sampling_priority=1)
            self.mock_extract.return_value = mock_context

            result = _extract_context_with_data_streams(context_json, event_type, arn)

            self.mock_extract.assert_called_once_with(context_json)
            self.mock_checkpoint.assert_not_called()
            self.assertEqual(result, mock_context)

    def test_extract_context_exception_path(self):
        with patch.dict(os.environ, {"DD_DATA_STREAMS_ENABLED": "true"}):
            context_json = {"dd-pathway-ctx-base64": "12345"}
            event_type = "sqs"
            arn = "arn:aws:sqs:us-east-1:123456789012:test-queue"

            mock_context = Context(trace_id=12345, span_id=67890, sampling_priority=1)
            self.mock_extract.return_value = mock_context

            test_exception = Exception("Test exception")
            self.mock_checkpoint.side_effect = test_exception

            result = _extract_context_with_data_streams(context_json, event_type, arn)

            self.mock_extract.assert_called_once_with(context_json)
            self.mock_checkpoint.assert_called_once()
            self.mock_logger.debug.assert_called_once()
            self.assertEqual(result, mock_context)


class TestCreateCarrierGet(unittest.TestCase):
    def test_create_carrier_get_with_valid_data(self):
        context_json = {
            "x-datadog-trace-id": "12345",
            "x-datadog-parent-id": "67890",
            "x-datadog-sampling-priority": "1",
        }

        carrier_get = _create_carrier_get(context_json)

        self.assertTrue(callable(carrier_get))
        self.assertEqual(carrier_get("x-datadog-trace-id"), "12345")
        self.assertEqual(carrier_get("x-datadog-parent-id"), "67890")
        self.assertEqual(carrier_get("x-datadog-sampling-priority"), "1")

    def test_create_carrier_get_with_missing_key(self):
        context_json = {"x-datadog-trace-id": "12345"}

        carrier_get = _create_carrier_get(context_json)

        self.assertTrue(callable(carrier_get))
        self.assertEqual(carrier_get("x-datadog-trace-id"), "12345")
        self.assertIsNone(carrier_get("x-datadog-parent-id"))

    def test_create_carrier_get_with_empty_context(self):
        context_json = {}

        carrier_get = _create_carrier_get(context_json)

        self.assertTrue(callable(carrier_get))
        self.assertIsNone(carrier_get("any-key"))


class TestExtractContextFromSqsOrSnsEvent(unittest.TestCase):
    def setUp(self):
        self.lambda_context = get_mock_context()

    @patch("datadog_lambda.tracing._extract_context_with_data_streams")
    def test_sqs_event_with_datadog_message_attributes(
        self, mock_extract_context_with_data_streams
    ):
        dd_data = {"dd-pathway-ctx-base64": "12345"}
        dd_json_data = json.dumps(dd_data)

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "messageAttributes": {
                        "_datadog": {"dataType": "String", "stringValue": dd_json_data}
                    },
                }
            ]
        }

        mock_context = Context(trace_id=12345, span_id=67890, sampling_priority=1)
        mock_extract_context_with_data_streams.return_value = mock_context

        result = extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context
        )

        mock_extract_context_with_data_streams.assert_called_once_with(
            dd_data, "sqs", "arn:aws:sqs:us-east-1:123456789012:test-queue"
        )
        self.assertEqual(result, mock_context)

    @patch("datadog_lambda.tracing._extract_context_with_data_streams")
    def test_sqs_event_with_binary_datadog_message_attributes(
        self, mock_extract_context_with_data_streams
    ):
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
                }
            ]
        }

        mock_context = Context(trace_id=12345, span_id=67890, sampling_priority=1)
        mock_extract_context_with_data_streams.return_value = mock_context

        result = extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context
        )

        mock_extract_context_with_data_streams.assert_called_once_with(
            dd_data, "sqs", "arn:aws:sqs:us-east-1:123456789012:test-queue"
        )
        self.assertEqual(result, mock_context)

    @patch("datadog_lambda.tracing._extract_context_with_data_streams")
    def test_sns_event_with_datadog_message_attributes(
        self, mock_extract_context_with_data_streams
    ):
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
                }
            ]
        }

        mock_context = Context(trace_id=12345, span_id=67890, sampling_priority=1)
        mock_extract_context_with_data_streams.return_value = mock_context

        result = extract_context_from_sqs_or_sns_event_or_context(
            event, self.lambda_context
        )

        mock_extract_context_with_data_streams.assert_called_once_with(
            dd_data, "sns", "arn:aws:sns:us-east-1:123456789012:test-topic"
        )
        self.assertEqual(result, mock_context)


class TestExtractContextFromKinesisEvent(unittest.TestCase):
    def setUp(self):
        self.lambda_context = get_mock_context()

    @patch("datadog_lambda.tracing._extract_context_with_data_streams")
    def test_kinesis_event_with_datadog_data(
        self, mock_extract_context_with_data_streams
    ):
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

        mock_context = Context(trace_id=12345, span_id=67890, sampling_priority=1)
        mock_extract_context_with_data_streams.return_value = mock_context

        result = extract_context_from_kinesis_event(event, self.lambda_context)

        mock_extract_context_with_data_streams.assert_called_once_with(
            dd_data,
            "kinesis",
            "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream",
        )
        self.assertEqual(result, mock_context)
