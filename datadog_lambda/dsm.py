import logging
import json
import base64

from datadog_lambda.trigger import EventTypes

logger = logging.getLogger(__name__)


def set_dsm_context(event, event_source):
    if event_source.equals(EventTypes.SQS):
        _dsm_set_sqs_context(event)
    elif event_source.equals(EventTypes.SNS):
        _dsm_set_sns_context(event)
    elif event_source.equals(EventTypes.KINESIS):
        _dsm_set_kinesis_context(event)


def _dsm_set_sqs_context(event):
    records = event.get("Records")
    if records is None:
        return

    for record in records:
        arn = record.get("eventSourceARN", "")
        _set_dsm_context_for_record(record, "sqs", arn)


def _dsm_set_sns_context(event):
    records = event.get("Records")
    if records is None:
        return

    for record in records:
        sns_data = record.get("Sns")
        if not sns_data:
            return
        arn = sns_data.get("TopicArn", "")
        _set_dsm_context_for_record(sns_data, "sns", arn)


def _dsm_set_kinesis_context(event):
    records = event.get("Records")
    if records is None:
        return

    for record in records:
        arn = record.get("eventSourceARN", "")
        _set_dsm_context_for_record(record, "kinesis", arn)


def _set_dsm_context_for_record(record, type, arn):
    from ddtrace.data_streams import set_consume_checkpoint

    try:
        context_json = _get_dsm_context_from_lambda(record)
        if not context_json:
            logger.debug("DataStreams skipped lambda message: %r", record)
            return

        carrier_get = _create_carrier_get(context_json)
        set_consume_checkpoint(type, arn, carrier_get)
    except Exception as e:
        logger.error(f"Unable to set dsm context: {e}")


def _get_dsm_context_from_lambda(message):
    """
    Lambda-specific message formats:
        - message.messageAttributes._datadog.stringValue (SQS -> lambda)
        - message.Sns.MessageAttributes._datadog.Value.decode() (SNS -> lambda)
        - message.kinesis.data.decode()._datadog (Kinesis -> lambda)
        - message.messageAttributes._datadog.binaryValue.decode() (SNS -> SQS -> lambda, raw)
        - message.body.MessageAttributes._datadog.Value.decode() (SNS -> SQS -> lambda)
    """
    context_json = None
    message_body = message

    if "kinesis" in message:
        try:
            kinesis_data = json.loads(
                base64.b64decode(message["kinesis"]["data"]).decode()
            )
            return kinesis_data.get("_datadog")
        except (ValueError, TypeError, KeyError):
            logger.debug("Unable to parse kinesis data for lambda message")
            return None
    elif "Sns" in message:
        message_body = message["Sns"]
    else:
        try:
            body = message.get("body")
            if body:
                parsed_body = json.loads(body)
                if "MessageAttributes" in parsed_body:
                    message_body = parsed_body
        except (ValueError, TypeError):
            logger.debug(
                "Unable to parse lambda message body as JSON, treat as non-json"
            )

    message_attributes = message_body.get("MessageAttributes") or message_body.get(
        "messageAttributes"
    )

    if not message_attributes:
        logger.debug("DataStreams skipped lambda message: %r", message)
        return None

    if "_datadog" not in message_attributes:
        logger.debug("DataStreams skipped lambda message: %r", message)
        return None

    datadog_attr = message_attributes["_datadog"]

    if message_body.get("Type") == "Notification":
        # SNS -> lambda notification
        if datadog_attr.get("Type") == "Binary":
            context_json = json.loads(base64.b64decode(datadog_attr["Value"]).decode())
    elif "stringValue" in datadog_attr:
        # SQS -> lambda
        context_json = json.loads(datadog_attr["stringValue"])
    elif "binaryValue" in datadog_attr:
        # SNS -> SQS -> lambda, raw message delivery
        context_json = json.loads(
            base64.b64decode(datadog_attr["binaryValue"]).decode()
        )
    else:
        logger.debug("DataStreams did not handle lambda message: %r", message)

    return context_json


def _create_carrier_get(context_json):
    def carrier_get(key):
        return context_json.get(key)

    return carrier_get
