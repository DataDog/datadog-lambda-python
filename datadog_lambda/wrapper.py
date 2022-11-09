# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import base64
import os
import logging
import traceback
from importlib import import_module
import json
from time import time_ns
from ddtrace.propagation.http import HTTPPropagator

from datadog_lambda.extension import should_use_extension, flush_extension
from datadog_lambda.cold_start import set_cold_start, is_cold_start
from datadog_lambda.constants import (
    TraceContextSource,
    XraySubsegment,
    Headers,
)
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
    mark_trace_as_error_for_5xx_responses,
    set_correlation_ids,
    set_dd_trace_py_root,
    create_function_execution_span,
    create_inferred_span,
    InferredSpanInfo,
)
from datadog_lambda.trigger import (
    extract_trigger_tags,
    extract_http_status_code_tag,
)
from datadog_lambda.tag_object import tag_object

profiling_env_var = os.environ.get("DD_PROFILING_ENABLED", "false").lower() == "true"
if profiling_env_var:
    from ddtrace.profiling import profiler

logger = logging.getLogger(__name__)

dd_capture_lambda_payload_enabled = (
    os.environ.get("DD_CAPTURE_LAMBDA_PAYLOAD", "false").lower() == "true"
)
service_env_var = os.environ.get("DD_SERVICE", "DefaultServiceName")
env_env_var = os.environ.get("DD_ENV", None)

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
            self.inferred_span = None
            self.make_inferred_span = (
                os.environ.get("DD_TRACE_MANAGED_SERVICES", "true").lower() == "true"
            )
            self.encode_authorizer_context = (
                os.environ.get("DD_ENCODE_AUTHORIZER_CONTEXT", "true").lower() == "true"
            )
            self.decode_authorizer_context = (
                os.environ.get("DD_DECODE_AUTHORIZER_CONTEXT", "true").lower() == "true"
            )
            self.response = None
            if profiling_env_var:
                self.prof = profiler.Profiler(env=env_env_var, service=service_env_var)
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

            # This prevents a breaking change in ddtrace v0.49 regarding the service name
            # in requests-related spans
            os.environ["DD_REQUESTS_SERVICE_NAME"] = os.environ.get(
                "DD_SERVICE", "aws.lambda"
            )
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

    def _inject_authorizer_span_headers(self, request_id, finish_time_ns):
        injected_headers = {}
        source_span = self.inferred_span if self.inferred_span else self.span
        HTTPPropagator.inject(source_span.context, injected_headers)
        # remove unused header
        injected_headers.pop(Headers.TAGS_HEADER_TO_DELETE, None)
        injected_headers[Headers.Parent_Span_Finish_Time] = finish_time_ns
        if request_id is not None:
            injected_headers[Headers.Authorizing_Request_Id] = request_id
        datadog_data = base64.b64encode(json.dumps(injected_headers).encode())
        self.response.setdefault("context", {})
        self.response["context"]["_datadog"] = datadog_data

    def _before(self, event, context):
        try:
            self.response = None
            set_cold_start()
            submit_invocations_metric(context)
            self.trigger_tags = extract_trigger_tags(event, context)
            # Extract Datadog trace context and source from incoming requests
            dd_context, trace_context_source, event_source = extract_dd_trace_context(
                event,
                context,
                extractor=self.trace_extractor,
                decode_authorizer_context=self.decode_authorizer_context,
            )
            self.event_source = event_source
            # Create a Datadog X-Ray subsegment with the trace context
            if dd_context and trace_context_source == TraceContextSource.EVENT:
                create_dd_dummy_metadata_subsegment(
                    dd_context, XraySubsegment.TRACE_KEY
                )

            if dd_tracing_enabled:
                set_dd_trace_py_root(trace_context_source, self.merge_xray_traces)
                if self.make_inferred_span:
                    self.inferred_span = create_inferred_span(
                        event, context, event_source
                    )
                self.span = create_function_execution_span(
                    context,
                    self.function_name,
                    is_cold_start(),
                    trace_context_source,
                    self.merge_xray_traces,
                    self.trigger_tags,
                    parent_span=self.inferred_span,
                )
            else:
                set_correlation_ids()
            if profiling_env_var and is_cold_start():
                self.prof.start(stop_on_exit=False, profile_children=True)
            logger.debug("datadog_lambda_wrapper _before() done")
        except Exception:
            traceback.print_exc()

    def _after(self, event, context):
        try:
            status_code = extract_http_status_code_tag(self.trigger_tags, self.response)
            if status_code:
                self.trigger_tags["http.status_code"] = status_code
                mark_trace_as_error_for_5xx_responses(context, status_code, self.span)

            # Create a new dummy Datadog subsegment for function trigger tags so we
            # can attach them to X-Ray spans when hybrid tracing is used
            if self.trigger_tags:
                create_dd_dummy_metadata_subsegment(
                    self.trigger_tags, XraySubsegment.LAMBDA_FUNCTION_TAGS_KEY
                )

            if self.span:
                if dd_capture_lambda_payload_enabled:
                    tag_object(self.span, "function.request", event)
                    tag_object(self.span, "function.response", self.response)

                if status_code:
                    self.span.set_tag("http.status_code", status_code)
                self.span.finish()

            if self.inferred_span:
                if status_code:
                    self.inferred_span.set_tag("http.status_code", status_code)

                if InferredSpanInfo.is_async(self.inferred_span) and self.span:
                    self.inferred_span.finish(finish_time=self.span.start)
                else:
                    self.inferred_span.finish()

            if not self.flush_to_log or should_use_extension:
                flush_stats()
            if should_use_extension:
                flush_extension()

            if (
                self.encode_authorizer_context
                and self.response
                and self.response.get("principalId")
                and self.response.get("policyDocument")
            ):
                # the finish_time_ns should be set as the end of the inferred span if it exist
                #  or the end of the current span
                reference_span = self.inferred_span if self.inferred_span else self.span
                finish_time_ns = (
                    reference_span.start_ns + reference_span.duration_ns
                    if reference_span is not None
                    and hasattr(reference_span, "start_ns")
                    and hasattr(reference_span, "duration_ns")
                    else time_ns()
                )
                self._inject_authorizer_span_headers(
                    event.get("requestContext", {}).get("requestId"), finish_time_ns
                )
            logger.debug("datadog_lambda_wrapper _after() done")
        except Exception:
            traceback.print_exc()


datadog_lambda_wrapper = _LambdaDecorator
