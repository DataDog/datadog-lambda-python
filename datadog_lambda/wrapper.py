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

from datadog_lambda.extension import should_use_extension, flush_extension
from datadog_lambda.cold_start import (
    set_cold_start,
    is_cold_start,
    is_proactive_init,
    is_new_sandbox,
    ColdStartTracer,
)
from datadog_lambda.constants import (
    TraceContextSource,
    XraySubsegment,
    Headers,
    TraceHeader,
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
    is_authorizer_response,
    tracer,
)
from datadog_lambda.trigger import (
    extract_trigger_tags,
    extract_http_status_code_tag,
)

profiling_env_var = os.environ.get("DD_PROFILING_ENABLED", "false").lower() == "true"
if profiling_env_var:
    from ddtrace.profiling import profiler

logger = logging.getLogger(__name__)

DD_FLUSH_TO_LOG = "DD_FLUSH_TO_LOG"
DD_LOGS_INJECTION = "DD_LOGS_INJECTION"
DD_MERGE_XRAY_TRACES = "DD_MERGE_XRAY_TRACES"
AWS_LAMBDA_FUNCTION_NAME = "AWS_LAMBDA_FUNCTION_NAME"
DD_LOCAL_TEST = "DD_LOCAL_TEST"
DD_TRACE_EXTRACTOR = "DD_TRACE_EXTRACTOR"
DD_TRACE_MANAGED_SERVICES = "DD_TRACE_MANAGED_SERVICES"
DD_ENCODE_AUTHORIZER_CONTEXT = "DD_ENCODE_AUTHORIZER_CONTEXT"
DD_DECODE_AUTHORIZER_CONTEXT = "DD_DECODE_AUTHORIZER_CONTEXT"
DD_COLD_START_TRACING = "DD_COLD_START_TRACING"
DD_MIN_COLD_START_DURATION = "DD_MIN_COLD_START_DURATION"
DD_COLD_START_TRACE_SKIP_LIB = "DD_COLD_START_TRACE_SKIP_LIB"
DD_CAPTURE_LAMBDA_PAYLOAD = "DD_CAPTURE_LAMBDA_PAYLOAD"
DD_CAPTURE_LAMBDA_PAYLOAD_MAX_DEPTH = "DD_CAPTURE_LAMBDA_PAYLOAD_MAX_DEPTH"
DD_REQUESTS_SERVICE_NAME = "DD_REQUESTS_SERVICE_NAME"
DD_SERVICE = "DD_SERVICE"
DD_ENV = "DD_ENV"


def get_env_as_int(env_key, default_value: int) -> int:
    try:
        return int(os.environ.get(env_key, default_value))
    except Exception as e:
        logger.warn(
            f"Failed to parse {env_key} as int. Using default value: {default_value}. Error: {e}"
        )
        return default_value


dd_capture_lambda_payload_enabled = (
    os.environ.get(DD_CAPTURE_LAMBDA_PAYLOAD, "false").lower() == "true"
)

if dd_capture_lambda_payload_enabled:
    import datadog_lambda.tag_object as tag_object

    tag_object.max_depth = get_env_as_int(
        DD_CAPTURE_LAMBDA_PAYLOAD_MAX_DEPTH, tag_object.max_depth
    )

env_env_var = os.environ.get(DD_ENV, None)

init_timestamp_ns = time_ns()

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
        except Exception as e:
            logger.error(format_err_with_traceback(e))
            return func

    def __init__(self, func):
        """Executes when the wrapped function gets wrapped"""
        try:
            self.func = func
            self.flush_to_log = os.environ.get(DD_FLUSH_TO_LOG, "").lower() == "true"
            self.logs_injection = (
                os.environ.get(DD_LOGS_INJECTION, "true").lower() == "true"
            )
            self.merge_xray_traces = (
                os.environ.get(DD_MERGE_XRAY_TRACES, "false").lower() == "true"
            )
            self.function_name = os.environ.get(AWS_LAMBDA_FUNCTION_NAME, "function")
            self.service = os.environ.get(DD_SERVICE, None)
            self.extractor_env = os.environ.get(DD_TRACE_EXTRACTOR, None)
            self.trace_extractor = None
            self.span = None
            self.inferred_span = None
            depends_on_dd_tracing_enabled = (
                lambda original_boolean: dd_tracing_enabled and original_boolean
            )
            self.make_inferred_span = depends_on_dd_tracing_enabled(
                os.environ.get(DD_TRACE_MANAGED_SERVICES, "true").lower() == "true"
            )
            self.encode_authorizer_context = depends_on_dd_tracing_enabled(
                os.environ.get(DD_ENCODE_AUTHORIZER_CONTEXT, "true").lower() == "true"
            )
            self.decode_authorizer_context = depends_on_dd_tracing_enabled(
                os.environ.get(DD_DECODE_AUTHORIZER_CONTEXT, "true").lower() == "true"
            )
            self.cold_start_tracing = depends_on_dd_tracing_enabled(
                os.environ.get(DD_COLD_START_TRACING, "true").lower() == "true"
            )
            self.min_cold_start_trace_duration = get_env_as_int(
                DD_MIN_COLD_START_DURATION, 3
            )
            self.local_testing_mode = os.environ.get(
                DD_LOCAL_TEST, "false"
            ).lower() in ("true", "1")
            self.cold_start_trace_skip_lib = [
                "ddtrace.internal.compat",
                "ddtrace.filters",
            ]
            if DD_COLD_START_TRACE_SKIP_LIB in os.environ:
                try:
                    self.cold_start_trace_skip_lib = os.environ[
                        DD_COLD_START_TRACE_SKIP_LIB
                    ].split(",")
                except Exception:
                    logger.debug(f"Malformatted for env {DD_COLD_START_TRACE_SKIP_LIB}")
            self.response = None
            if profiling_env_var:
                self.prof = profiler.Profiler(env=env_env_var, service=self.service)
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
            os.environ[DD_REQUESTS_SERVICE_NAME] = os.environ.get(
                DD_SERVICE, "aws.lambda"
            )
            # Patch third-party libraries for tracing
            patch_all()

            logger.debug("datadog_lambda_wrapper initialized")
        except Exception as e:
            logger.error(format_err_with_traceback(e))

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

    def _inject_authorizer_span_headers(self, request_id):
        reference_span = self.inferred_span if self.inferred_span else self.span
        assert reference_span.finished
        # the finish_time_ns should be set as the end of the inferred span if it exist
        #  or the end of the current span
        finish_time_ns = (
            reference_span.start_ns + reference_span.duration_ns
            if reference_span is not None
            and hasattr(reference_span, "start_ns")
            and hasattr(reference_span, "duration_ns")
            else time_ns()
        )
        injected_headers = {}
        source_span = self.inferred_span if self.inferred_span else self.span
        span_context = source_span.context
        injected_headers[TraceHeader.TRACE_ID] = str(span_context.trace_id)
        injected_headers[TraceHeader.PARENT_ID] = str(span_context.span_id)
        sampling_priority = span_context.sampling_priority
        if sampling_priority is not None:
            injected_headers[TraceHeader.SAMPLING_PRIORITY] = str(
                span_context.sampling_priority
            )
        injected_headers[Headers.Parent_Span_Finish_Time] = finish_time_ns
        if request_id is not None:
            injected_headers[Headers.Authorizing_Request_Id] = request_id
        datadog_data = base64.b64encode(json.dumps(injected_headers).encode()).decode()
        self.response.setdefault("context", {})
        self.response["context"]["_datadog"] = datadog_data

    def _before(self, event, context):
        try:
            self.response = None
            set_cold_start(init_timestamp_ns)
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
                    {
                        "trace-id": str(dd_context.trace_id),
                        "parent-id": str(dd_context.span_id),
                        "sampling-priority": str(dd_context.sampling_priority),
                    },
                    XraySubsegment.TRACE_KEY,
                )

            if dd_tracing_enabled:
                set_dd_trace_py_root(trace_context_source, self.merge_xray_traces)
                if self.make_inferred_span:
                    self.inferred_span = create_inferred_span(
                        event, context, event_source, self.decode_authorizer_context
                    )
                self.span = create_function_execution_span(
                    context,
                    self.function_name,
                    is_cold_start(),
                    is_proactive_init(),
                    trace_context_source,
                    self.merge_xray_traces,
                    self.trigger_tags,
                    parent_span=self.inferred_span,
                )
            else:
                set_correlation_ids()
            if profiling_env_var and is_new_sandbox():
                self.prof.start(stop_on_exit=False, profile_children=True)
            logger.debug("datadog_lambda_wrapper _before() done")
        except Exception as e:
            logger.error(format_err_with_traceback(e))

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
            should_trace_cold_start = self.cold_start_tracing and is_new_sandbox()
            if should_trace_cold_start:
                trace_ctx = tracer.current_trace_context()

            if self.span:
                if dd_capture_lambda_payload_enabled:
                    tag_object.tag_object(self.span, "function.request", event)
                    tag_object.tag_object(self.span, "function.response", self.response)

                if status_code:
                    self.span.set_tag("http.status_code", status_code)
                self.span.finish()

            if self.inferred_span:
                if status_code:
                    self.inferred_span.set_tag("http.status_code", status_code)

                if self.service:
                    self.inferred_span.set_tag("peer.service", self.service)

                if InferredSpanInfo.is_async(self.inferred_span) and self.span:
                    self.inferred_span.finish(finish_time=self.span.start)
                else:
                    self.inferred_span.finish()

            if should_trace_cold_start:
                try:
                    following_span = self.span or self.inferred_span
                    ColdStartTracer(
                        tracer,
                        self.function_name,
                        following_span.start_ns,
                        trace_ctx,
                        self.min_cold_start_trace_duration,
                        self.cold_start_trace_skip_lib,
                    ).trace()
                except Exception as e:
                    logger.debug("Failed to create cold start spans. %s", e)

            if not self.flush_to_log or should_use_extension:
                flush_stats()
            if should_use_extension and self.local_testing_mode:
                # when testing locally, the extension does not know when an
                # invocation completes because it does not have access to the
                # logs api
                flush_extension()

            if self.encode_authorizer_context and is_authorizer_response(self.response):
                self._inject_authorizer_span_headers(
                    event.get("requestContext", {}).get("requestId")
                )
            logger.debug("datadog_lambda_wrapper _after() done")
        except Exception as e:
            logger.error(format_err_with_traceback(e))


def format_err_with_traceback(e):
    return "Error {}. Traceback: {}".format(
        e, traceback.format_exc().replace("\n", "\r")
    )


datadog_lambda_wrapper = _LambdaDecorator
