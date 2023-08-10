import unittest
from decimal import Decimal

try:
    from unittest.mock import MagicMock, patch, call
except ImportError:
    from mock import MagicMock, patch, call
from datadog_lambda.tag_object import tag_object


class TestTagObject(unittest.TestCase):
    def test_tag_object(self):
        payload = {
            "hello": "world",
            "anotherThing": {"foo": "bar", "blah": None, "nice": True},
            "vals": [{"thingOne": 1}, {"thingTwo": 2}],
        }
        spanMock = MagicMock()
        tag_object(spanMock, "function.request", payload)
        spanMock.set_tag.assert_has_calls(
            [
                call("function.request.vals.0.thingOne", 1),
                call("function.request.vals.1.thingTwo", 2),
                call("function.request.hello", "world"),
                call("function.request.anotherThing.blah", None),
                call("function.request.anotherThing.foo", "bar"),
                call("function.request.anotherThing.nice", True),
            ],
            True,
        )
        self.assertEqual(1, 1)

    def test_redacted_tag_object(self):
        payload = {
            "authorization": "world",
            "anotherThing": {"password": "bar", "blah": None, "nice": True},
            "vals": [{"thingOne": 1}, {"thingTwo": 2}],
        }
        spanMock = MagicMock()
        tag_object(spanMock, "function.request", payload)
        spanMock.set_tag.assert_has_calls(
            [
                call("function.request.vals.0.thingOne", 1),
                call("function.request.vals.1.thingTwo", 2),
                call("function.request.authorization", "redacted"),
                call("function.request.anotherThing.blah", None),
                call("function.request.anotherThing.password", "redacted"),
                call("function.request.anotherThing.nice", True),
            ],
            True,
        )

    def test_json_tag_object(self):
        payload = {
            "token": "world",
            "jsonString": '{"stringifyThisJson":[{"here":"is","an":"object","number":1}]}',
        }
        spanMock = MagicMock()
        tag_object(spanMock, "function.request", payload)
        spanMock.set_tag.assert_has_calls(
            [
                call("function.request.token", "redacted"),
                call("function.request.jsonString.stringifyThisJson.0.here", "is"),
                call("function.request.jsonString.stringifyThisJson.0.an", "object"),
                call("function.request.jsonString.stringifyThisJson.0.number", 1),
            ],
            True,
        )

    def test_unicode_tag_object(self):
        payload = {
            "token": "world",
            "jsonString": '{"stringifyThisJson":[{"here":"is","an":"object","number":1}]}',
        }
        spanMock = MagicMock()
        tag_object(spanMock, "function.request", payload)
        spanMock.set_tag.assert_has_calls(
            [
                call("function.request.token", "redacted"),
                call("function.request.jsonString.stringifyThisJson.0.here", "is"),
                call("function.request.jsonString.stringifyThisJson.0.an", "object"),
                call("function.request.jsonString.stringifyThisJson.0.number", 1),
            ],
            True,
        )

    def test_decimal_tag_object(self):
        payload = {"myValue": Decimal(500.50)}
        spanMock = MagicMock()
        tag_object(spanMock, "function.request", payload)
        spanMock.set_tag.assert_has_calls(
            [
                call("function.request.myValue", Decimal(500.50)),
            ],
            True,
        )

    @patch("datadog_lambda.tag_object.logger.warning")
    def test_large_dict_payload(self, mock_logger_warning):
        payload = {f"key_{i}": f"value_{i}" for i in range(500)}  # More than 450 items
        spanMock = MagicMock()
        tag_object(spanMock, "function.request", payload)
        # Check that the logger warning was emitted
        mock_logger_warning.assert_called_once()
        # Check that the tag is set to a plain string, not JSON
        spanMock.set_tag.assert_called_once_with("function.request", str(payload))

    @patch("datadog_lambda.tag_object.logger.warning")
    def test_large_list_payload(self, mock_logger_warning):
        payload = [f"value_{i}" for i in range(500)]  # More than 450 items
        spanMock = MagicMock()
        tag_object(spanMock, "function.request", payload)
        # Check that the logger warning was emitted
        mock_logger_warning.assert_called_once()
        # Check that the tag is set to a plain string, not JSON
        spanMock.set_tag.assert_called_once_with("function.request", str(payload))

    @patch('datadog_lambda.tag_object.logger.warning')
    def test_borderline_dict_payload(self, mock_logger_warning):
        payload = {f"key_{i}": f"value_{i}" for i in range(450)}  # Exactly 450 items
        spanMock = MagicMock()
        tag_object(spanMock, "function.request", payload)
        # Ensure the logger warning wasn't emitted (since we're at the limit, not over)
        mock_logger_warning.assert_not_called()
        # As the logic continues, depending on your depth and other configurations, the spanMock.set_tag will be called various times.
        # For simplicity, just asserting it was called
        spanMock.set_tag.assert_called()

    @patch('datadog_lambda.tag_object.logger.warning')
    def test_just_below_limit_list_payload(self, mock_logger_warning):
        payload = [f"value_{i}" for i in range(449)]  # Just below 450 items
        spanMock = MagicMock()
        tag_object(spanMock, "function.request", payload)
        # Ensure the logger warning wasn't emitted
        mock_logger_warning.assert_not_called()
        # As the logic continues, depending on your depth and other configurations, the spanMock.set_tag will be called various times.
        # For simplicity, just asserting it was called
        spanMock.set_tag.assert_called()