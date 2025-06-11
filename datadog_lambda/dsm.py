import logging
import json
from datadog_lambda.trigger import EventTypes

logger = logging.getLogger(__name__)


def set_dsm_context(event, event_source):
    if event_source.equals(EventTypes.SQS):
        _dsm_set_sqs_context(event)


def _dsm_set_sqs_context(event):
    from ddtrace.data_streams import set_consume_checkpoint

    records = event.get("Records")
    if records is None:
        return

    for record in records:
        arn = record.get("eventSourceARN", "")
        context_json = _get_dsm_context_from_lambda(record)
        if not context_json:
            logger.debug("DataStreams skipped lambda message: %r", record)
            return None

        def carrier_get(key):
            return context_json.get(key)

        set_consume_checkpoint("sqs", arn, carrier_get)


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
