# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import os
import logging
import traceback
from importlib import import_module

from datadog_lambda.extension import should_use_extension, flush_extension
from datadog_lambda.cold_start import set_cold_start, is_cold_start
from datadog_lambda.constants import XraySubsegment, TraceContextSource
from datadog_lambda.metric import (
    flush_stats,
    submit_invocations_metric,
    submit_errors_metric,
)
from datadog_lambda.module_name import modify_module_name
from datadog_lambda.patch import patch_all
from datadog_lambda.tracing import (
    extract_dd_trace_context,
    create_dd_dummy_metadata_subsegment,
    inject_correlation_ids,
    dd_tracing_enabled,
    set_correlation_ids,
    set_dd_trace_py_root,
    create_function_execution_span,
)
from datadog_lambda.trigger import extract_trigger_tags, extract_http_status_code_tag
from datadog_lambda.tag_object import tag_object

logger = logging.getLogger(__name__)

dd_capture_lambda_payload_enabled = (
    os.environ.get("DD_CAPTURE_LAMBDA_PAYLOAD", "false").lower() == "true"
)

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
            self.merge_xray_traces = (
                os.environ.get("DD_MERGE_XRAY_TRACES", "false").lower() == "true"
            )
            self.function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "function")
            self.extractor_env = os.environ.get("DD_TRACE_EXTRACTOR", None)
            self.trace_extractor = None
            self.span = None
            self.response = None

            if self.extractor_env:
                extractor_parts = self.extractor_env.rsplit(".", 1)
                if len(extractor_parts) == 2:
                    (mod_name, extractor_name) = extractor_parts
                    modified_extractor_name = modify_module_name(mod_name)
                    extractor_module = import_module(modified_extractor_name)
                    self.trace_extractor = getattr(extractor_module, extractor_name)

            # Inject trace correlation ids to logs
            if self.logs_injection:
                inject_correlation_ids()

            # Patch third-party libraries for tracing
            patch_all()

            logger.debug("datadog_lambda_wrapper initialized")
        except Exception:
            traceback.print_exc()

    def __call__(self, event, context, **kwargs):
        """Executes when the wrapped function gets called"""
        self._before(event, context)
        try:
            self.response = self.func(event, context, **kwargs)
            return self.response
        except Exception:
            submit_errors_metric(context)
            if self.span:
                self.span.set_traceback()
            raise
        finally:
            self._after(event, context)

    def _before(self, event, context):
        try:
            set_cold_start()
            submit_invocations_metric(context)
            self.trigger_tags = extract_trigger_tags(event, context)
            # Extract Datadog trace context and source from incoming requests
            dd_context, trace_context_source = extract_dd_trace_context(
                event, context, extractor=self.trace_extractor
            )
            # Create a Datadog X-Ray subsegment with the trace context
            if dd_context and trace_context_source == TraceContextSource.EVENT:
                create_dd_dummy_metadata_subsegment(
                    dd_context, XraySubsegment.TRACE_KEY
                )

            if dd_tracing_enabled:
                set_dd_trace_py_root(trace_context_source, self.merge_xray_traces)
                self.span = create_function_execution_span(
                    context,
                    self.function_name,
                    is_cold_start(),
                    trace_context_source,
                    self.merge_xray_traces,
                    self.trigger_tags,
                )
            else:
                set_correlation_ids()

            logger.debug("datadog_lambda_wrapper _before() done")
        except Exception:
            traceback.print_exc()

    def _after(self, event, context):
        try:
            status_code = extract_http_status_code_tag(self.trigger_tags, self.response)
            if status_code:
                self.trigger_tags["http.status_code"] = status_code
            # Create a new dummy Datadog subsegment for function trigger tags so we
            # can attach them to X-Ray spans when hybrid tracing is used
            if self.trigger_tags:
                create_dd_dummy_metadata_subsegment(
                    self.trigger_tags, XraySubsegment.LAMBDA_FUNCTION_TAGS_KEY
                )

            if not self.flush_to_log or should_use_extension:
                flush_stats()
            if should_use_extension:
                flush_extension()

            if self.span:
                if dd_capture_lambda_payload_enabled:
                    tag_object(self.span, "function.request", event)
                    tag_object(self.span, "function.response", self.response)

                if status_code:
                    self.span.set_tag("http.status_code", status_code)
                self.span.finish()
            logger.debug("datadog_lambda_wrapper _after() done")
        except Exception:
            traceback.print_exc()


datadog_lambda_wrapper = _LambdaDecorator
