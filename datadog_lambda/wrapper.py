# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import os
import logging
import traceback

from datadog_lambda.cold_start import set_cold_start
from datadog_lambda.metric import (
    lambda_stats,
    submit_invocations_metric,
    submit_errors_metric,
)
from datadog_lambda.patch import patch_all
from datadog_lambda.tracing import (
    extract_dd_trace_context,
    set_correlation_ids,
    inject_correlation_ids,
)


logger = logging.getLogger(__name__)


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


class _NoopDecorator(object):

    def __init__(self, func):
        self.func = func

    def __call__(self, *args, **kwargs):
        return self.func(*args, **kwargs)


class _LambdaDecorator(object):
    """
    Decorator to automatically initialize Datadog API client, flush metrics,
    and extracts/injects trace context.
    """

    _force_wrap = False

    def __new__(cls, func):
        """
        If the decorator is accidentally applied to the same function multiple times,
        wrap only once.

        If _force_wrap, always return a real decorator, useful for unit tests.
        """
        try:
            if cls._force_wrap or not isinstance(func, _LambdaDecorator):
                wrapped = super(_LambdaDecorator, cls).__new__(cls)
                logger.debug("datadog_lambda_wrapper wrapped")
                return wrapped
            else:
                logger.debug("datadog_lambda_wrapper already wrapped")
                return _NoopDecorator(func)
        except Exception:
            traceback.print_exc()
            return func

    def __init__(self, func):
        """Executes when the wrapped function gets wrapped"""
        try:
            self.func = func
            self.flush_to_log = os.environ.get("DD_FLUSH_TO_LOG", "").lower() == "true"
            self.logs_injection = (
                os.environ.get("DD_LOGS_INJECTION", "true").lower() == "true"
            )

            # Inject trace correlation ids to logs
            if self.logs_injection:
                inject_correlation_ids()

            # Patch HTTP clients to propagate Datadog trace context
            patch_all()
            logger.debug("datadog_lambda_wrapper initialized")
        except Exception:
            traceback.print_exc()

    def __call__(self, event, context, **kwargs):
        """Executes when the wrapped function gets called"""
        self._before(event, context)
        try:
            return self.func(event, context, **kwargs)
        except Exception:
            submit_errors_metric(context)
            raise
        finally:
            self._after(event, context)

    def _before(self, event, context):
        try:
            set_cold_start()
            submit_invocations_metric(context)
            # Extract Datadog trace context from incoming requests
            extract_dd_trace_context(event)

            # Set log correlation ids using extracted trace context
            set_correlation_ids()
            logger.debug("datadog_lambda_wrapper _before() done")
        except Exception:
            traceback.print_exc()

    def _after(self, event, context):
        try:
            if not self.flush_to_log:
                lambda_stats.flush(float("inf"))
            logger.debug("datadog_lambda_wrapper _after() done")
        except Exception:
            traceback.print_exc()


datadog_lambda_wrapper = _LambdaDecorator
