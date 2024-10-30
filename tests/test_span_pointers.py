from typing import List
from typing import NamedTuple

from ddtrace._trace._span_pointer import _SpanPointerDirection
from ddtrace._trace._span_pointer import _SpanPointerDescription
from datadog_lambda.trigger import _EventSource
from datadog_lambda.trigger import EventTypes
from datadog_lambda.span_pointers import calculate_span_pointers
import pytest


class TestCalculateSpanPointers:
    class SpanPointersCase(NamedTuple):
        name: str
        event_source: _EventSource
        event: dict
        span_pointers: List[_SpanPointerDescription]

    @pytest.mark.parametrize(
        "test_case",
        [
            SpanPointersCase(
                name="some unsupported event",
                event_source=_EventSource(EventTypes.UNKNOWN),
                event={},
                span_pointers=[],
            ),
            SpanPointersCase(
                name="empty s3 event",
                event_source=_EventSource(EventTypes.S3),
                event={},
                span_pointers=[],
            ),
            SpanPointersCase(
                name="sensible s3 event",
                event_source=_EventSource(EventTypes.S3),
                event={
                    "Records": [
                        {
                            "eventName": "ObjectCreated:Put",
                            "s3": {
                                "bucket": {
                                    "name": "mybucket",
                                },
                                "object": {
                                    "key": "mykey",
                                    "eTag": "123abc",
                                },
                            },
                        },
                    ],
                },
                span_pointers=[
                    _SpanPointerDescription(
                        pointer_kind="aws.s3.object",
                        pointer_direction=_SpanPointerDirection.UPSTREAM,
                        pointer_hash="8d49f5b0b742484159d4cd572bae1ce5",
                        extra_attributes={},
                    ),
                ],
            ),
            SpanPointersCase(
                name="malformed s3 event",
                event_source=_EventSource(EventTypes.S3),
                event={
                    "Records": [
                        {
                            "eventName": "ObjectCreated:Put",
                            "s3": {
                                "bucket": {
                                    "name": "mybucket",
                                },
                                "object": {
                                    "key": "mykey",
                                    # missing eTag
                                },
                            },
                        },
                    ],
                },
                span_pointers=[],
            ),
            SpanPointersCase(
                name="empty dynamodb event",
                event_source=_EventSource(EventTypes.DYNAMODB),
                event={},
                span_pointers=[],
            ),
            SpanPointersCase(
                name="sensible dynamodb event",
                event_source=_EventSource(EventTypes.DYNAMODB),
                event={
                    "Records": [
                        {
                            "eventSourceARN": "arn:aws:dynamodb:us-west-2:123456789012:table/some-table/stream/2015-06-27T00:48:05.899",
                            "dynamodb": {
                                "Keys": {
                                    "some-key": {"S": "some-value"},
                                },
                            },
                        },
                        {
                            "eventSourceARN": "arn:aws:dynamodb:us-west-2:123456789012:table/some-table/stream/2015-06-27T00:48:05.899",
                            "dynamodb": {
                                "Keys": {
                                    "some-key": {"S": "some-other-value"},
                                },
                            },
                        },
                    ],
                },
                span_pointers=[
                    _SpanPointerDescription(
                        pointer_kind="aws.dynamodb.item",
                        pointer_direction=_SpanPointerDirection.UPSTREAM,
                        pointer_hash="7f1aee721472bcb48701d45c7c7f7821",
                        extra_attributes={},
                    ),
                    _SpanPointerDescription(
                        pointer_kind="aws.dynamodb.item",
                        pointer_direction=_SpanPointerDirection.UPSTREAM,
                        pointer_hash="36b820424312a6069bd3f2185f1af584",
                        extra_attributes={},
                    ),
                ],
            ),
            SpanPointersCase(
                name="malformed dynamodb event",
                event_source=_EventSource(EventTypes.DYNAMODB),
                event={
                    "Records": [
                        {
                            "eventSourceARN": "arn:aws:dynamodb:us-west-2:123456789012:table/some-table",  # missing stream info
                            "dynamodb": {
                                "Keys": {
                                    "some-key": {"S": "some-value"},
                                },
                            },
                        },
                    ],
                },
                span_pointers=[],
            ),
        ],
        ids=lambda test_case: test_case.name,
    )
    def test_calculate_span_pointers(self, test_case: SpanPointersCase):
        assert (
            calculate_span_pointers(
                test_case.event_source,
                test_case.event,
            )
            == test_case.span_pointers
        )
