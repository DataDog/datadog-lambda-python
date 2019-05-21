# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import os
import traceback

from datadog_lambda.metric import lambda_stats
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
        self.flush_to_log = os.environ.get('DATADOG_FLUSH_TO_LOG') == 'True'

    def _before(self, event, context):
        try:
            # Extract Datadog trace context from incoming requests
            extract_dd_trace_context(event)

            # Patch HTTP clients to propogate Datadog trace context
            patch_all()
        except Exception:
            traceback.print_exc()

    def _after(self, event, context):
        try:
            if not self.flush_to_log:
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
