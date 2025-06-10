import json
import logging

from datadog_lambda.trigger import EventTypes

logger = logging.getLogger(__name__)


def set_dsm_context(event, event_source):
    if event_source.equals(EventTypes.SQS):
        _dsm_set_sqs_context(event)


def _dsm_set_context_helper(service_type, arn, payload_size, context_json):
    """
    Common helper function for setting DSM context.

    Args:
        service_type: The service type string (example: sqs', 'sns')
        arn:  ARN from the record
        payload_size: payload size of the record
        context_json: Datadog context for the record
    """
    from ddtrace.internal.datastreams import data_streams_processor
    from ddtrace.internal.datastreams.processor import DsmPathwayCodec

    processor = data_streams_processor()

    try:
        ctx = DsmPathwayCodec.decode(context_json, processor)
        ctx.set_checkpoint(
            ["direction:in", f"topic:{arn}", f"type:{service_type}"],
            payload_size=payload_size,
        )
    except Exception as e:
        logger.error(f"Unable to set dsm context: {e}")


def _dsm_set_sqs_context(event):
    from ddtrace.internal.datastreams.botocore import calculate_sqs_payload_size

    records = event.get("Records")
    if records is None:
        return

    for record in records:
        arn = record.get("eventSourceARN", "")
        context_json = _get_dsm_context_from_lambda(record)
        payload_size = calculate_sqs_payload_size(record, context_json)

        _dsm_set_context_helper("sqs", arn, payload_size, context_json)


def _get_dsm_context_from_lambda(message):
    """
    Lambda-specific message formats:
        - message.messageAttributes._datadog.stringValue (SQS -> lambda)
    """
    context_json = None
    message_attributes = message.get("messageAttributes")
    if not message_attributes:
        logger.debug("DataStreams skipped lambda message: %r", message)
        return None

    if "_datadog" not in message_attributes:
        logger.debug("DataStreams skipped lambda message: %r", message)
        return None

    datadog_attr = message_attributes["_datadog"]

    if "stringValue" in datadog_attr:
        # SQS -> lambda
        context_json = json.loads(datadog_attr["stringValue"])
    else:
        logger.debug("DataStreams did not handle lambda message: %r", message)

    return context_json
