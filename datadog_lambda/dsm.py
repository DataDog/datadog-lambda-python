import logging
import json
from datadog_lambda.trigger import EventTypes

logger = logging.getLogger(__name__)


def set_dsm_context(event, event_source):
    if event_source.equals(EventTypes.SQS):
        _dsm_set_sqs_context(event)


def _dsm_set_sqs_context(event):
    records = event.get("Records")
    if records is None:
        return

    for record in records:
        try:
            arn = record.get("eventSourceARN", "")
            context_json = _get_dsm_context_from_sqs_lambda(record)
            if not context_json:
                continue
            _set_dsm_context_for_record(context_json, "sqs", arn)

        except Exception as e:
            logger.error(f"Unable to set dsm context: {e}")


def _set_dsm_context_for_record(context_json, type, arn):
    from ddtrace.data_streams import set_consume_checkpoint

    carrier_get = _create_carrier_get(context_json)
    set_consume_checkpoint(type, arn, carrier_get, manual_checkpoint=False)


def _get_dsm_context_from_sqs_lambda(message):
    """
    Lambda-specific message shape for SQS -> Lambda:
        - message.messageAttributes._datadog.stringValue
    """
    context_json = None
    message_attributes = message.get("messageAttributes")
    if not message_attributes:
        logger.debug(
            "DataStreams skipped lambda message, no messageAttributes, message: %r",
            message,
        )
        return None

    if "_datadog" not in message_attributes:
        logger.debug(
            "DataStreams skipped lambda message, no datadog context, message: %r",
            message,
        )
        return None

    datadog_attr = message_attributes["_datadog"]

    if "stringValue" in datadog_attr:
        context_json = json.loads(datadog_attr["stringValue"])
        if not isinstance(context_json, dict):
            logger.debug(
                "DataStreams did not handle lambda message, context is not a dict, message: %r",
                message,
            )
            return None
    else:
        logger.debug(
            "DataStreams did not handle lambda message, no dsm context, message: %r",
            message,
        )

    return context_json


def _create_carrier_get(context_json):
    def carrier_get(key):
        return context_json.get(key)

    return carrier_get
