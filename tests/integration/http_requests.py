import os
import requests

from decorator import conditional_decorator
from datadog_lambda.metric import lambda_metric
from datadog_lambda.wrapper import datadog_lambda_wrapper
from ddtrace import tracer
from ddtrace.internal.writer import LogWriter

tracer.writer = LogWriter()

with_plugin = os.getenv('WITH_PLUGIN', False);

@conditional_decorator(datadog_lambda_wrapper, with_plugin)
def handle(event, context):
    lambda_metric("hello.dog", 1, tags=["team:serverless", "role:hello"])
    lambda_metric(
        "tests.integration.count", 21, tags=["test:integration", "role:hello"]
    )

    requests.get("https://ip-ranges.datadoghq.com/")
    requests.get("https://ip-ranges.datadoghq.eu/")

    return {"statusCode": 200, "body": {"message": "hello, dog!"}}
