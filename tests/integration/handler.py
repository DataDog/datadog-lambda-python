import json

from datadog_lambda.metric import lambda_metric
from datadog_lambda.wrapper import datadog_lambda_wrapper


@datadog_lambda_wrapper
def handle(event, context):
    lambda_metric("hello.dog", 1)
    return {"statusCode": 200, "body": "hello, dog!"}
