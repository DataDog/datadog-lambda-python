from datadog_lambda import logger
from datadog_lambda.trigger import EventTypes


def set_dsm_context(event, event_source):

    if event_source.equals(EventTypes.SQS):
        _dsm_set_sqs_context(event)


def _dsm_set_sqs_context(event):
    from datadog_lambda.wrapper import format_err_with_traceback

    from ddtrace.internal.datastreams.processor import (
        DataStreamsProcessor as processor,
        DsmPathwayCodec,
    )
    from ddtrace.internal.datastreams.botocore import (
        get_datastreams_context,
        calculate_sqs_payload_size,
    )

    records = event.get("Records", [])
    for record in records:
        try:
            queue_arn = record.get("eventSourceARN", "")

            contextjson = get_datastreams_context(record)
            payload_size = calculate_sqs_payload_size(record)

            ctx = DsmPathwayCodec.decode(contextjson, processor())
            ctx.set_checkpoint(
                ["direction:in", f"topic:{queue_arn}, "type:sqs"],
                payload_size=payload_size,
            )
        except Exception as e:
            logger.error(format_err_with_traceback(e))
