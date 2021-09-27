import unittest

try:
    from unittest.mock import MagicMock, patch, call
except ImportError:
    from mock import MagicMock, patch, call
from datadog_lambda.tag_object import tag_object


class TestTagObject(unittest.TestCase):
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
