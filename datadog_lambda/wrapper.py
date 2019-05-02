import traceback
from threading import Thread

from datadog_lambda.metric import init_api_client, lambda_stats
from datadog_lambda.tracing import extract_dd_trace_context
from datadog_lambda.patch import patch_all


"""
Usage:

import requests
from datadog_lambda.wrapper import datadog_lambda_wrapper
from datadog_lambda.metric import lambda_metric

@datadog_lambda_wrapper
def my_lambda_handle(event, context):
    lambda_metric("my_metric", 10)
    requests.get("https://www.datadoghq.com")
"""


class _LambdaDecorator(object):
    """
    Decorator to automatically initialize Datadog API client, flush metrics,
    and extracts/injects trace context.
    """

    def __init__(self, func):
        self.func = func

    def _before(self, event, context):
        try:
            # Async initialization of the TLS connection with Datadog API,
            # and reduces the overhead to the final metric flush at the end.
            Thread(target=init_api_client).start()

            # Extract Datadog trace context from incoming requests
            extract_dd_trace_context(event)

            # Patch HTTP clients to propogate Datadog trace context
            patch_all()
        except Exception:
            traceback.print_exc()

    def _after(self, event, context):
        try:
            lambda_stats.flush(float("inf"))
        except Exception:
            traceback.print_exc()

    def __call__(self, event, context):
        self._before(event, context)
        try:
            return self.func(event, context)
        finally:
            self._after(event, context)


datadog_lambda_wrapper = _LambdaDecorator
