import unittest
from unittest.mock import patch, MagicMock

from datadog_lambda.dsm import set_dsm_context, _dsm_set_sqs_context
from datadog_lambda.trigger import EventTypes


class TestDsmContext(unittest.TestCase):
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
        event = {"Records": [{"body": "test"}]}

        mock_event_source = MagicMock()
        mock_event_source.equals.return_value = False  # Not SQS

        set_dsm_context(event, mock_event_source)

        mock_event_source.equals.assert_called_once_with(EventTypes.SQS)
        self.mock_dsm_set_sqs_context.assert_not_called()

    def test_event_with_no_records_does_nothing(self):
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

        mock_event_source = MagicMock()
        mock_event_source.equals.return_value = True

        set_dsm_context(sqs_event, mock_event_source)

        self.mock_dsm_set_sqs_context.assert_called_once_with(sqs_event)

    def test_multiple_records_process_each_record(self):
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
