import unittest
import json
from unittest.mock import patch, MagicMock

from datadog_lambda.dsm import (
    set_dsm_context,
    _dsm_set_sqs_context,
    _get_dsm_context_from_lambda,
)
from datadog_lambda.trigger import EventTypes, _EventSource


class TestDSMContext(unittest.TestCase):
    def setUp(self):
        patcher = patch("datadog_lambda.dsm._dsm_set_sqs_context")
        self.mock_dsm_set_sqs_context = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("ddtrace.internal.datastreams.data_streams_processor")
        self.mock_data_streams_processor = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("ddtrace.internal.datastreams.botocore.get_datastreams_context")
        self.mock_get_datastreams_context = patcher.start()
        self.mock_get_datastreams_context.return_value = {}
        self.addCleanup(patcher.stop)

        patcher = patch(
            "ddtrace.internal.datastreams.botocore.calculate_sqs_payload_size"
        )
        self.mock_calculate_sqs_payload_size = patcher.start()
        self.mock_calculate_sqs_payload_size.return_value = 100
        self.addCleanup(patcher.stop)

        patcher = patch("ddtrace.internal.datastreams.processor.DsmPathwayCodec.decode")
        self.mock_dsm_pathway_codec_decode = patcher.start()
        self.addCleanup(patcher.stop)

    def test_non_sqs_event_source_does_nothing(self):
        """Test that non-SQS event sources don't trigger DSM context setting"""
        event = {}
        # Use Unknown Event Source
        event_source = _EventSource(EventTypes.UNKNOWN)
        set_dsm_context(event, event_source)

        # DSM context should not be set for non-SQS events
        self.mock_dsm_set_sqs_context.assert_not_called()

    def test_sqs_event_with_no_records_does_nothing(self):
        """Test that events where Records is None don't trigger DSM processing"""
        events_with_no_records = [
            {},
            {"Records": None},
            {"someOtherField": "value"},
        ]

        for event in events_with_no_records:
            _dsm_set_sqs_context(event)
            self.mock_data_streams_processor.assert_not_called()

    def test_sqs_event_triggers_dsm_sqs_context(self):
        """Test that SQS event sources trigger the SQS-specific DSM context function"""
        sqs_event = {
            "Records": [
                {
                    "eventSource": "aws:sqs",
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:my-queue",
                    "body": "Hello from SQS!",
                }
            ]
        }

        event_source = _EventSource(EventTypes.SQS)
        set_dsm_context(sqs_event, event_source)

        self.mock_dsm_set_sqs_context.assert_called_once_with(sqs_event)

    def test_sqs_multiple_records_process_each_record(self):
        """Test that each record in an SQS event gets processed individually"""
        multi_record_event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:queue1",
                    "body": "Message 1",
                },
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:queue2",
                    "body": "Message 2",
                },
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:queue3",
                    "body": "Message 3",
                },
            ]
        }

        mock_context = MagicMock()
        self.mock_dsm_pathway_codec_decode.return_value = mock_context

        _dsm_set_sqs_context(multi_record_event)

        self.assertEqual(mock_context.set_checkpoint.call_count, 3)

        calls = mock_context.set_checkpoint.call_args_list
        expected_arns = [
            "arn:aws:sqs:us-east-1:123456789012:queue1",
            "arn:aws:sqs:us-east-1:123456789012:queue2",
            "arn:aws:sqs:us-east-1:123456789012:queue3",
        ]

        for i, call in enumerate(calls):
            args, kwargs = call
            tags = args[0]
            self.assertIn("direction:in", tags)
            self.assertIn(f"topic:{expected_arns[i]}", tags)
            self.assertIn("type:sqs", tags)
            self.assertEqual(kwargs["payload_size"], 100)


class TestGetDSMContext(unittest.TestCase):
    def test_sqs_to_lambda_string_value_format(self):
        """Test format: message.messageAttributes._datadog.stringValue (SQS -> lambda)"""
        trace_context = {
            "x-datadog-trace-id": "789123456",
            "x-datadog-parent-id": "321987654",
            "dd-pathway-ctx": "test-pathway-ctx",
        }

        lambda_record = {
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
                    "stringValue": json.dumps(trace_context),
                    "stringListValues": [],
                    "binaryListValues": [],
                    "dataType": "String",
                },
                "myAttribute": {
                    "stringValue": "myValue",
                    "stringListValues": [],
                    "binaryListValues": [],
                    "dataType": "String",
                },
            },
            "md5OfBody": "e4e68fb7bd0e697a0ae8f1bb342846b3",
            "eventSource": "aws:sqs",
            "eventSourceARN": "arn:aws:sqs:us-east-2:123456789012:my-queue",
            "awsRegion": "us-east-2",
        }

        result = _get_dsm_context_from_lambda(lambda_record)

        assert result is not None
        assert result == trace_context
        assert result["x-datadog-trace-id"] == "789123456"
        assert result["x-datadog-parent-id"] == "321987654"
        assert result["dd-pathway-ctx"] == "test-pathway-ctx"

    def test_no_message_attributes(self):
        """Test message without MessageAttributes returns None."""
        message = {
            "messageId": "test-message-id",
            "body": "Test message without attributes",
        }

        result = _get_dsm_context_from_lambda(message)

        assert result is None

    def test_no_datadog_attribute(self):
        """Test message with MessageAttributes but no _datadog attribute returns None."""
        message = {
            "messageId": "test-message-id",
            "body": "Test message",
            "messageAttributes": {
                "customAttribute": {"stringValue": "custom-value", "dataType": "String"}
            },
        }

        result = _get_dsm_context_from_lambda(message)
        assert result is None

    def test_empty_datadog_attribute(self):
        """Test message with empty _datadog attribute returns None."""
        message = {
            "messageId": "test-message-id",
            "messageAttributes": {"_datadog": {}},
        }

        result = _get_dsm_context_from_lambda(message)

        assert result is None
