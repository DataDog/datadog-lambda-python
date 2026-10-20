"""Short-invocation smoke handler; use an exposure-enabled string test flag."""

import json
import os
import time
import uuid

from datadog_lambda.wrapper import datadog_lambda_wrapper
from ddtrace.openfeature import DataDogProvider
from openfeature import api
from openfeature.evaluation_context import EvaluationContext

provider = DataDogProvider()
api.set_provider(provider)
client = api.get_client("lambda-flush-smoke")
sandbox_id = uuid.uuid4().hex
invocations = 0


@datadog_lambda_wrapper
def handle(event, context):
    global invocations
    invocations += 1
    started = time.monotonic()
    subject = event["subject"]
    details = client.get_string_details(
        os.environ["FFL_SMOKE_FLAG_KEY"],
        "smoke-default",
        EvaluationContext(targeting_key=subject),
    )
    result = {
        "request_id": context.aws_request_id,
        "sandbox_id": sandbox_id,
        "invocation": invocations,
        "subject": subject,
        "value": details.value,
        "variant": details.variant,
        "error_code": str(details.error_code) if details.error_code else None,
        "evaluation_ms": (time.monotonic() - started) * 1000,
    }
    # Only synthetic test subjects belong in this smoke-test log.
    print(json.dumps(result))
    if details.error_code:
        raise RuntimeError(
            "Smoke flag did not resolve; verify test flag and configuration"
        )
    if event.get("raise"):
        raise RuntimeError("intentional smoke-test handler failure")
    return result
