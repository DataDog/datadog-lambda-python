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
