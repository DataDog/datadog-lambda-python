import requests

from datadog_lambda.metric import lambda_metric
from datadog_lambda.wrapper import datadog_lambda_wrapper


@datadog_lambda_wrapper
def handle(event, context):
    # Parse request ID and record IDs out of the event to include in the response
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

    # Generate custom metrics
    lambda_metric("hello.dog", 1, tags=["team:serverless", "role:hello"])
    lambda_metric(
        "tests.integration.count", 21, tags=["test:integration", "role:hello"]
    )

    # Make HTTP calls to test ddtrace instrumentation
    requests.get("https://httpstat.us/200/")
    requests.get("https://httpstat.us/400/")

    return {
        "statusCode": 200,
        "body": {
            "message": "hello, dog!",
            "request_id": request_id,
            "event_record_ids": record_ids,
        },
    }
