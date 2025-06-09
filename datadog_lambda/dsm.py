import json
import base64

from ddtrace.internal.logger import get_logger
from datadog_lambda import logger
from datadog_lambda.trigger import EventTypes

log = get_logger(__name__)


def set_dsm_context(event, event_source):
    if event_source.equals(EventTypes.SQS):
        _dsm_set_sqs_context(event)
    elif event_source.equals(EventTypes.SNS):
        _dsm_set_sns_context(event)
    elif event_source.equals(EventTypes.KINESIS):
        _dsm_set_kinesis_context(event)


def _dsm_set_context_helper(
    event, service_type, arn_extractor, payload_size_calculator
):
    """
    Common helper function for setting DSM context.

    Args:
        event: The Lambda event containing records
        service_type: The service type string (example: sqs', 'sns')
        arn_extractor: Function to extract the ARN from the record
        payload_size_calculator: Function to calculate payload size
    """
    from datadog_lambda.wrapper import format_err_with_traceback
    from ddtrace.internal.datastreams import data_streams_processor
    from ddtrace.internal.datastreams.processor import DsmPathwayCodec

    records = event.get("Records")
    if records is None:
        return
    processor = data_streams_processor()

    for record in records:
        try:
            arn = arn_extractor(record)
            context_json = _get_dsm_context_from_lambda(record)
            payload_size = payload_size_calculator(record, context_json)

            ctx = DsmPathwayCodec.decode(context_json, processor)
            ctx.set_checkpoint(
                ["direction:in", f"topic:{arn}", f"type:{service_type}"],
                payload_size=payload_size,
            )
        except Exception as e:
            logger.error(format_err_with_traceback(e))


def _dsm_set_sns_context(event):
    from ddtrace.internal.datastreams.botocore import calculate_sns_payload_size

    def sns_payload_calculator(record, context_json):
        return calculate_sns_payload_size(record, context_json)

    def sns_arn_extractor(record):
        sns_data = record.get("Sns")
        if not sns_data:
            return ""
        return sns_data.get("TopicArn", "")

    _dsm_set_context_helper(event, "sns", sns_arn_extractor, sns_payload_calculator)


def _dsm_set_sqs_context(event):
    from ddtrace.internal.datastreams.botocore import calculate_sqs_payload_size

    def sqs_payload_calculator(record, context_json):
        return calculate_sqs_payload_size(record)

    def sqs_arn_extractor(record):
        return record.get("eventSourceARN", "")

    _dsm_set_context_helper(event, "sqs", sqs_arn_extractor, sqs_payload_calculator)


def _dsm_set_kinesis_context(event):
    from ddtrace.internal.datastreams.botocore import calculate_kinesis_payload_size

    def kinesis_payload_calculator(record, context_json):
        return calculate_kinesis_payload_size(record)

    def kinesis_arn_extractor(record):
        arn = record.get("eventSourceARN")
        if arn is None:
            return ""
        return arn

    _dsm_set_context_helper(
        event, "kinesis", kinesis_arn_extractor, kinesis_payload_calculator
    )


def _get_dsm_context_from_lambda(message):
    """
    Lambda-specific message formats:
        - message.messageAttributes._datadog.stringValue (SQS -> lambda)
        - message.Sns.MessageAttributes._datadog.Value.decode() (SNS -> lambda)
        - message.messageAttributes._datadog.binaryValue.decode() (SNS -> SQS -> lambda, raw)
        - message.body.MessageAttributes._datadog.Value.decode() (SNS -> SQS -> lambda)
        - message.kinesis.data.decode()._datadog (Kinesis -> lambda)
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
            log.debug("Unable to parse kinesis data for lambda message")
            return None
    elif "Sns" in message:
        message_body = message["Sns"]
    else:
        try:
            body = message.get("body")
            if body:
                message_body = json.loads(body)
        except (ValueError, TypeError):
            log.debug("Unable to parse lambda message body as JSON, treat as non-json")

    message_attributes = message_body.get("MessageAttributes") or message_body.get(
        "messageAttributes"
    )
    if not message_attributes:
        log.debug("DataStreams skipped lambda message: %r", message)
        return None

    if "_datadog" not in message_attributes:
        log.debug("DataStreams skipped lambda message: %r", message)
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
        log.debug("DataStreams did not handle lambda message: %r", message)

    return context_json
