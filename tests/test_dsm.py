import unittest
from unittest.mock import patch
import json
import base64

from datadog_lambda.trigger import EventTypes, _EventSource, parse_event_source
from tests.utils import get_mock_context

from datadog_lambda.dsm import set_dsm_context


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

        set_dsm_context(event, parse_event_source(event))

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

        set_dsm_context(event, parse_event_source(event))

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

        set_dsm_context(event, parse_event_source(event))
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

        set_dsm_context(event, parse_event_source(event))
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

        set_dsm_context(event, parse_event_source(event))

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    @patch("datadog_lambda.dsm.logger")
    def test_sqs_invalid_datadog_message_attribute(self, mock_dsm_logger):
        event = {
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
        }

        set_dsm_context(event, parse_event_source(event))

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

        self.mock_checkpoint.reset_mock()
        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue",
                    "messageAttributes": {
                        "_datadog": {
                            "dataType": "Number",
                            "numberValue": 123,
                        }
                    },
                    "eventSource": "aws:sqs",
                }
            ]
        }

        set_dsm_context(event, parse_event_source(event))

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
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

        set_dsm_context(event, parse_event_source(event))

        self.mock_checkpoint.assert_not_called()

    @patch("datadog_lambda.config.Config.data_streams_enabled", False)
    def test_sqs_data_streams_disabled(self):
        context_json = {"dd-pathway-ctx-base64": "12345"}

        set_dsm_context(context_json, _EventSource(EventTypes.SQS))

        self.mock_checkpoint.assert_not_called()

    def test_sqs_multiple_records(self):
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
                },
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue-2",
                    "messageAttributes": {
                        "_datadog": {"dataType": "String", "stringValue": dd_json_data}
                    },
                    "eventSource": "aws:sqs",
                },
            ]
        }

        set_dsm_context(event, parse_event_source(event))

        # Should be called once for each record
        self.assertEqual(self.mock_checkpoint.call_count, 2)

        # Check first call
        first_call_args = self.mock_checkpoint.call_args_list[0][0]
        self.assertEqual(first_call_args[0], "sqs")
        self.assertEqual(
            first_call_args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue"
        )
        carrier_get = first_call_args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

        # Check second call
        second_call_args = self.mock_checkpoint.call_args_list[1][0]
        self.assertEqual(second_call_args[0], "sqs")
        self.assertEqual(
            second_call_args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue-2"
        )
        carrier_get = second_call_args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

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

        set_dsm_context(event, parse_event_source(event))

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

        set_dsm_context(event, parse_event_source(event))

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

        set_dsm_context(event, parse_event_source(event))
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

        set_dsm_context(event, parse_event_source(event))
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

        set_dsm_context(event, parse_event_source(event))

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sns")
        self.assertEqual(args[1], "arn:aws:sns:us-east-1:123456789012:test-topic")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    @patch("datadog_lambda.dsm.logger")
    def test_sns_invalid_datadog_message_attribute(self, mock_dsm_logger):
        event = {
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
        }

        set_dsm_context(event, parse_event_source(event))

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sns")
        self.assertEqual(args[1], "arn:aws:sns:us-east-1:123456789012:test-topic")
        carrier_get = args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

        self.mock_checkpoint.reset_mock()

        event = {
            "Records": [
                {
                    "Sns": {
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
                        "MessageAttributes": {
                            "_datadog": {
                                "Type": "Number",
                                "numberValue": 123,
                            }
                        },
                    },
                    "eventSource": "aws:sns",
                }
            ]
        }

        set_dsm_context(event, parse_event_source(event))

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sns")
        self.assertEqual(args[1], "arn:aws:sns:us-east-1:123456789012:test-topic")
        carrier_get = args[2]
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

        set_dsm_context(event, parse_event_source(event))

        self.mock_checkpoint.assert_not_called()

    @patch("datadog_lambda.config.Config.data_streams_enabled", False)
    def test_sns_data_streams_disabled(self):
        context_json = {"dd-pathway-ctx-base64": "12345"}

        set_dsm_context(context_json, _EventSource(EventTypes.SNS))

        self.mock_checkpoint.assert_not_called()

    def test_sns_multiple_records(self):
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
                },
                {
                    "eventSourceARN": "",
                    "Sns": {
                        "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic-2",
                        "MessageAttributes": {
                            "_datadog": {"Type": "String", "Value": dd_json_data}
                        },
                    },
                    "eventSource": "aws:sns",
                },
            ]
        }

        set_dsm_context(event, parse_event_source(event))

        # Should be called once for each record
        self.assertEqual(self.mock_checkpoint.call_count, 2)

        # Check first call
        first_call_args = self.mock_checkpoint.call_args_list[0][0]
        self.assertEqual(first_call_args[0], "sns")
        self.assertEqual(
            first_call_args[1], "arn:aws:sns:us-east-1:123456789012:test-topic"
        )
        carrier_get = first_call_args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

        # Check second call
        second_call_args = self.mock_checkpoint.call_args_list[1][0]
        self.assertEqual(second_call_args[0], "sns")
        self.assertEqual(
            second_call_args[1], "arn:aws:sns:us-east-1:123456789012:test-topic-2"
        )
        carrier_get = second_call_args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

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

        set_dsm_context(event, parse_event_source(event))

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

        set_dsm_context(event, parse_event_source(event))
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

        set_dsm_context(event, parse_event_source(event))
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

        set_dsm_context(event, parse_event_source(event))
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

        set_dsm_context(event, parse_event_source(event))

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        # Should use SQS ARN, not SNS ARN
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    @patch("datadog_lambda.dsm.logger")
    def test_sns_to_sqs_invalid_datadog_message_attribute(self, mock_dsm_logger):
        sns_notification = {
            "Type": "Notification",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
            "MessageAttributes": {
                "_datadog": {"Type": "Binary", "Value": "not-base64"}
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

        set_dsm_context(event, parse_event_source(event))

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

        self.mock_checkpoint.reset_mock()

        sns_notification = {
            "Type": "Notification",
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:test-topic",
            "MessageAttributes": {
                "_datadog": {
                    "Type": "Number",
                    "numberValue": 123,
                }
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

        set_dsm_context(event, parse_event_source(event))

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "sqs")
        self.assertEqual(args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue")
        carrier_get = args[2]
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

        set_dsm_context(event, parse_event_source(event))

        self.mock_checkpoint.assert_not_called()

    @patch("datadog_lambda.config.Config.data_streams_enabled", False)
    def test_sns_to_sqs_data_streams_disabled(self):
        context_json = {"dd-pathway-ctx-base64": "12345"}

        set_dsm_context(context_json, _EventSource(EventTypes.SQS))

        self.mock_checkpoint.assert_not_called()

    def test_sns_to_sqs_multiple_records(self):
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
                },
                {
                    "eventSourceARN": "arn:aws:sqs:us-east-1:123456789012:test-queue-2",
                    "body": json.dumps(sns_notification),
                    "eventSource": "aws:sqs",
                },
            ]
        }

        set_dsm_context(event, parse_event_source(event))

        # Should be called once for each record
        self.assertEqual(self.mock_checkpoint.call_count, 2)

        # Check first call
        first_call_args = self.mock_checkpoint.call_args_list[0][0]
        self.assertEqual(first_call_args[0], "sqs")
        self.assertEqual(
            first_call_args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue"
        )
        carrier_get = first_call_args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

        # Check second call
        second_call_args = self.mock_checkpoint.call_args_list[1][0]
        self.assertEqual(second_call_args[0], "sqs")
        self.assertEqual(
            second_call_args[1], "arn:aws:sqs:us-east-1:123456789012:test-queue-2"
        )
        carrier_get = second_call_args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

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

        set_dsm_context(event, _EventSource(EventTypes.KINESIS))

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

        set_dsm_context(event, _EventSource(EventTypes.KINESIS))

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

        set_dsm_context(event, _EventSource(EventTypes.KINESIS))
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

        set_dsm_context(event, _EventSource(EventTypes.KINESIS))

        self.assertEqual(self.mock_checkpoint.call_count, 1)
        args, _ = self.mock_checkpoint.call_args
        self.assertEqual(args[0], "kinesis")
        self.assertEqual(
            args[1], "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream"
        )
        carrier_get = args[2]
        # None indicates no DSM context propagation
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), None)

    @patch("datadog_lambda.dsm.logger")
    def test_kinesis_invalid_datadog_message_attribute(self, mock_logger):
        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream",
                    "kinesis": {"data": "invalid-base64"},
                }
            ]
        }

        set_dsm_context(event, _EventSource(EventTypes.KINESIS))

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

        set_dsm_context(event, _EventSource(EventTypes.KINESIS))

        self.mock_checkpoint.assert_not_called()

    @patch("datadog_lambda.config.Config.data_streams_enabled", False)
    def test_kinesis_data_streams_disabled(self):
        context_json = {"dd-pathway-ctx-base64": "12345"}
        set_dsm_context(context_json, _EventSource(EventTypes.KINESIS))

        self.mock_checkpoint.assert_not_called()

    def test_kinesis_multiple_records(self):
        dd_data = {"dd-pathway-ctx-base64": "12345"}
        kinesis_data = {"_datadog": dd_data, "message": "test"}
        kinesis_data_str = json.dumps(kinesis_data)
        encoded_data = base64.b64encode(kinesis_data_str.encode()).decode()

        event = {
            "Records": [
                {
                    "eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream",
                    "kinesis": {"data": encoded_data},
                },
                {
                    "eventSourceARN": "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream-2",
                    "kinesis": {"data": encoded_data},
                },
            ]
        }

        set_dsm_context(event, _EventSource(EventTypes.KINESIS))

        self.assertEqual(self.mock_checkpoint.call_count, 2)

        first_call_args = self.mock_checkpoint.call_args_list[0][0]
        self.assertEqual(first_call_args[0], "kinesis")
        self.assertEqual(
            first_call_args[1],
            "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream",
        )
        carrier_get = first_call_args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

        second_call_args = self.mock_checkpoint.call_args_list[1][0]
        self.assertEqual(second_call_args[0], "kinesis")
        self.assertEqual(
            second_call_args[1],
            "arn:aws:kinesis:us-east-1:123456789012:stream/test-stream-2",
        )
        carrier_get = second_call_args[2]
        self.assertEqual(carrier_get("dd-pathway-ctx-base64"), "12345")

    # Unkown event source

    def test_unknown_event_source(self):
        event = {"unknown": "event"}

        set_dsm_context(event, _EventSource(EventTypes.UNKNOWN))

        self.mock_checkpoint.assert_not_called()
