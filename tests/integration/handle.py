import os

from decorator import conditional_decorator
from datadog_lambda.metric import lambda_metric
from datadog_lambda.wrapper import datadog_lambda_wrapper

with_plugin = os.getenv('WITH_PLUGIN', False) == 'true';

@conditional_decorator(datadog_lambda_wrapper, with_plugin)
def handle(event, context):
    # Parse request ID and record ids out of the event to include in the response
    request_id = event.get("requestContext", {}).get("requestId")
    event_records = event.get("Records", [])

    record_ids = []
    for record in event_records:
        # SQS
        if record.get("messageId"):
            record_ids.append(record["messageId"])
        # SNS
        if record.get("Sns", {}).get("MessageId"):
            record_ids.append(record["Sns"]["MessageId"])

    lambda_metric("hello.dog", 1, tags=["team:serverless", "role:hello"])
    lambda_metric(
        "tests.integration.count", 21, tags=["test:integration", "role:hello"]
    )

    return {
        "statusCode": 200,
        "body": {
            "message": "hello, dog!",
            "request_id": request_id,
            "event_record_ids": record_ids,
        },
    }
