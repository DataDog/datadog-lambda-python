import logging
from datadog_lambda.trigger import EventTypes, _EventSource
from datadog_lambda.tracing import (
    extract_context_from_kinesis_record,
    extract_context_from_sqs_or_sns_record,
)

logger = logging.getLogger(__name__)


def set_dsm_context(event, event_source: _EventSource):
    if (
        not event_source.equals(EventTypes.KINESIS)
        and not event_source.equals(EventTypes.SNS)
        and not event_source.equals(EventTypes.SQS)
    ):
        logger.debug(
            f"DSM:{event_source.to_string()} not supported, not setting checkpoint"
        )
        return

    for record in event.get("Records", []):
        source_arn = (
            record.get("Sns", {}).get("TopicArn")
            if event_source.equals(EventTypes.SNS)
            else record.get("eventSourceARN")
        )

        if not source_arn:
            logger.debug(
                f"DSM:No source arn found, not setting checkpoint for record: {record}"
            )
            continue
        try:
            from ddtrace.data_streams import set_consume_checkpoint

            # Allowed to be None, DSM checkpoint will still be set
            context_json = None
            try:
                context_json = (
                    extract_context_from_kinesis_record(record.get("kinesis", {}))
                    if event_source.equals(EventTypes.KINESIS)
                    else extract_context_from_sqs_or_sns_record(record)
                )
            except Exception as e:
                logger.debug(
                    f"DSM:Failed to extract context from {source_arn} with error: {e}. "
                    f"Will still attempt to set checkpoint."
                )

            carrier_get = lambda k: context_json and context_json.get(k)  # noqa: E731
            set_consume_checkpoint(
                event_source.to_string(),
                source_arn,
                carrier_get,
                manual_checkpoint=False,
            )
        except Exception as e:
            logger.debug(
                f"DSM:Failed to set consume checkpoint for {source_arn} with error: {e}"
            )
