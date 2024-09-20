from itertools import chain
import logging
from typing import List

from ddtrace._trace.utils_botocore.span_pointers import _aws_s3_object_span_pointer_description
from ddtrace._trace._span_pointer import _SpanPointerDirection
from ddtrace._trace._span_pointer import _SpanPointerDescription
from datadog_lambda.trigger import EventTypes


logger = logging.getLogger(__name__)


def calculate_span_pointers(
    event_source,
    event,
) -> List[_SpanPointerDescription]:
    try:
        if event_source.equals(EventTypes.S3):
            return _calculate_s3_span_pointers_for_event(event)

    except Exception as e:
        logger.warning(
            "failed to calculate span pointers for event: %s",
            str(e),
        )

    return []


def _calculate_s3_span_pointers_for_event(event) -> List[_SpanPointerDescription]:
    # Example event:
    # https://docs.aws.amazon.com/lambda/latest/dg/with-s3.html

    return list(
        chain.from_iterable(
            _calculate_s3_span_pointers_for_event_record(record)
            for record in event.get("Records", [])
        )
    )


def _calculate_s3_span_pointers_for_event_record(record) -> List[_SpanPointerDescription]:
    # Event types:
    # https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html

    if record.get("eventName").startswith("ObjectCreated:"):
        s3_information = record.get("s3", None)
        if s3_information is not None:
            return _calculate_s3_span_pointers_for_object_created_s3_information(s3_information)

    return []


def _calculate_s3_span_pointers_for_object_created_s3_information(
    s3_information
) -> List[_SpanPointerDescription]:
    try:
        bucket = s3_information["bucket"]["name"]
        key = s3_information["object"]["key"]
        etag = s3_information["object"]["eTag"]

    except KeyError as e:
        logger.warning(
            "missing s3 information required to make a span pointer: %s",
            str(e),
        )
        return []

    try:
        return [
            _aws_s3_object_span_pointer_description(
                pointer_direction=_SpanPointerDirection.UPSTREAM,
                bucket=bucket,
                key=key,
                etag=etag,
            )
        ]

    except Exception as e:
        logger.warning(
            "failed to generate S3 span pointer: %s",
            str(e),
        )
        return []
