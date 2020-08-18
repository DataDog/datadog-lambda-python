import requests

from datadog_lambda.metric import lambda_metric
from datadog_lambda.wrapper import datadog_lambda_wrapper
from ddtrace import tracer
from ddtrace.internal.writer import LogWriter

tracer.writer = LogWriter()


@datadog_lambda_wrapper
def handle(event, context):
    lambda_metric("hello.dog", 1, tags=["team:serverless", "role:hello"])
    lambda_metric(
        "tests.integration.count", 21, tags=["test:integration", "role:hello"]
    )

    requests.get("httpstat.us/400")
    requests.get("httpstat.us/500")

    return {"statusCode": 200, "body": {"message": "hello, dog!"}}
