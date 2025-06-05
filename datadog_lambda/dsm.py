from datadog_lambda import logger
from datadog_lambda.trigger import EventTypes


def set_dsm_context(event, event_source):
    if event_source.equals(EventTypes.SQS):
        _dsm_set_sqs_context(event)
    elif event_source.equals(EventTypes.SNS):
        _dsm_set_sns_context(event)


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
    from ddtrace.internal.datastreams.botocore import get_datastreams_context

    records = event.get("Records")
    if records is None:
        return
    processor = data_streams_processor()

    for record in records:
        try:
            arn = arn_extractor(record)
            context_json = get_datastreams_context(record)
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
