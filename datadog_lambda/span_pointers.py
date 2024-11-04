from itertools import chain
import logging
import os
from typing import List

from ddtrace._trace._span_pointer import _SpanPointerDirection
from ddtrace._trace._span_pointer import _SpanPointerDescription
from datadog_lambda.trigger import EventTypes


logger = logging.getLogger(__name__)


dd_botocore_add_span_pointers = os.environ.get("DD_BOTOCORE_ADD_SPAN_POINTERS", "true").lower() in ("true", "1")


def calculate_span_pointers(
    event_source,
    event,
    botocore_add_span_pointers=dd_botocore_add_span_pointers,
) -> List[_SpanPointerDescription]:
    try:
        if botocore_add_span_pointers:
            if event_source.equals(EventTypes.S3):
                return _calculate_s3_span_pointers_for_event(event)

            elif event_source.equals(EventTypes.DYNAMODB):
                return _calculate_dynamodb_span_pointers_for_event(event)

    except Exception as e:
        logger.warning(
            "failed to calculate span pointers for event: %s",
            e,
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


def _calculate_s3_span_pointers_for_event_record(
    record,
) -> List[_SpanPointerDescription]:
    # Event types:
    # https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html

    if record.get("eventName").startswith("ObjectCreated:"):
        s3_information = record.get("s3", None)
        if s3_information is not None:
            return _calculate_s3_span_pointers_for_object_created_s3_information(
                s3_information
            )

    return []


def _calculate_s3_span_pointers_for_object_created_s3_information(
    s3_information,
) -> List[_SpanPointerDescription]:
    try:
        bucket = s3_information["bucket"]["name"]
        key = s3_information["object"]["key"]
        etag = s3_information["object"]["eTag"]

    except KeyError as e:
        logger.warning(
            "missing s3 information required to make a span pointer: %s",
            e,
        )
        return []

    try:
        from ddtrace._trace.utils_botocore.span_pointers.s3 import (
            _aws_s3_object_span_pointer_description,
        )

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
            e,
        )
        return []


def _calculate_dynamodb_span_pointers_for_event(event) -> List[_SpanPointerDescription]:
    # Example event:
    # https://docs.aws.amazon.com/lambda/latest/dg/with-ddb.html

    return list(
        chain.from_iterable(
            _calculate_dynamodb_span_pointers_for_event_record(record)
            for record in event.get("Records", [])
        )
    )


def _calculate_dynamodb_span_pointers_for_event_record(
    record,
) -> List[_SpanPointerDescription]:
    try:
        table_name = _extract_table_name_from_dynamodb_stream_record(record)
        primary_key = record["dynamodb"]["Keys"]

    except Exception as e:
        logger.warning(
            "missing DynamoDB information required to make a span pointer: %s",
            e,
        )
        return []

    try:
        from ddtrace._trace.utils_botocore.span_pointers.dynamodb import (
            _aws_dynamodb_item_span_pointer_description,
        )

        return [
            _aws_dynamodb_item_span_pointer_description(
                pointer_direction=_SpanPointerDirection.UPSTREAM,
                table_name=table_name,
                primary_key=primary_key,
            )
        ]

    except Exception as e:
        logger.warning(
            "failed to generate DynamoDB span pointer: %s",
            e,
        )
        return []


def _extract_table_name_from_dynamodb_stream_record(record) -> str:
    # Example eventSourceARN:
    # arn:aws:dynamodb:us-east-2:123456789012:table/my-table/stream/2024-06-10T19:26:16.525
    event_source_arn = record["eventSourceARN"]

    [_arn, _aws, _dynamodb, _region, _account, dynamodb_info] = event_source_arn.split(
        ":", maxsplit=5
    )
    if _arn != "arn" or _aws != "aws" or _dynamodb != "dynamodb":
        raise ValueError(f"unexpected eventSourceARN format: {event_source_arn}")

    [_table, table_name, _stream, _timestamp] = dynamodb_info.split("/")
    if _table != "table" or _stream != "stream":
        raise ValueError(f"unexpected eventSourceARN format: {event_source_arn}")

    return table_name
