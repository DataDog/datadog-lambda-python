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
