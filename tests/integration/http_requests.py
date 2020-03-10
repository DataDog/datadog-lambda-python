import json
import requests

from datadog_lambda.metric import lambda_metric
from datadog_lambda.wrapper import datadog_lambda_wrapper


@datadog_lambda_wrapper
def handle(event, context):
    lambda_metric("hello.dog", 1, tags=["team:serverless", "role:hello"])
    lambda_metric(
        "tests.integration.count", 21, tags=["test:integration", "role:hello"]
    )

    us_response = requests.get("https://ip-ranges.datadoghq.com/")
    eu_response = requests.get("https://ip-ranges.datadoghq.eu/")

    return {"statusCode": 200, "body": {"message": "hello, dog!"}}
