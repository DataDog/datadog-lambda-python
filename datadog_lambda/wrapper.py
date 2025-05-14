# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.
import os
import logging
import traceback
import ujson as json
from importlib import import_module
from time import time_ns

from datadog_lambda.dsm import set_dsm_context
from datadog_lambda.extension import should_use_extension, flush_extension
from datadog_lambda.cold_start import (
    set_cold_start,
    is_cold_start,
    is_proactive_init,
    is_new_sandbox,
    ColdStartTracer,
)
from datadog_lambda.config import config
from datadog_lambda.constants import (
    TraceContextSource,
    XraySubsegment,
    Headers,
)
from datadog_lambda.module_name import modify_module_name
from datadog_lambda.patch import patch_all
from datadog_lambda.span_pointers import calculate_span_pointers
from datadog_lambda.tag_object import tag_object
from datadog_lambda.tracing import (
    extract_dd_trace_context,
    create_dd_dummy_metadata_subsegment,
    inject_correlation_ids,
    mark_trace_as_error_for_5xx_responses,
    set_correlation_ids,
    set_dd_trace_py_root,
    create_function_execution_span,
    create_inferred_span,
    InferredSpanInfo,
    is_authorizer_response,
    tracer,
    propagator,
)
from datadog_lambda.trigger import (
    extract_trigger_tags,
    extract_http_status_code_tag,
)

# Patch third-party libraries for tracing, must be done before importing any
# handler code.
patch_all()

if config.profiling_enabled:
    from ddtrace.profiling import profiler

if config.llmobs_enabled:
    from ddtrace.llmobs import LLMObs

if config.exception_replay_enabled:
    from ddtrace.debugging._exception.replay import SpanExceptionHandler
    from ddtrace.debugging._uploader import LogsIntakeUploaderV1

logger = logging.getLogger(__name__)

DD_REQUESTS_SERVICE_NAME = "DD_REQUESTS_SERVICE_NAME"
DD_SERVICE = "DD_SERVICE"

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
            self.trace_extractor = None
            self.span = None
            self.inferred_span = None
            self.response = None

            if config.profiling_enabled:
                self.prof = profiler.Profiler(env=config.env, service=config.service)

            if config.trace_extractor:
                extractor_parts = config.trace_extractor.rsplit(".", 1)
                if len(extractor_parts) == 2:
                    (mod_name, extractor_name) = extractor_parts
                    modified_extractor_name = modify_module_name(mod_name)
                    extractor_module = import_module(modified_extractor_name)
                    self.trace_extractor = getattr(extractor_module, extractor_name)

            # Inject trace correlation ids to logs
            if config.logs_injection:
                inject_correlation_ids()

            # This prevents a breaking change in ddtrace v0.49 regarding the service name
            # in requests-related spans
            os.environ[DD_REQUESTS_SERVICE_NAME] = os.environ.get(
                DD_SERVICE, "aws.lambda"
            )

            # Enable LLM Observability
            if config.llmobs_enabled:
                LLMObs.enable()

            # Enable Exception Replay
            if config.exception_replay_enabled:
                logger.debug("Enabling exception replay")
                SpanExceptionHandler.enable()

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
            if not should_use_extension:
                from datadog_lambda.metric import submit_errors_metric

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
        propagator.inject(span_context, injected_headers)
        injected_headers[Headers.Parent_Span_Finish_Time] = finish_time_ns
        if request_id is not None:
            injected_headers[Headers.Authorizing_Request_Id] = request_id

        import base64

        datadog_data = base64.b64encode(
            json.dumps(injected_headers, escape_forward_slashes=False).encode()
        ).decode()
        self.response.setdefault("context", {})
        self.response["context"]["_datadog"] = datadog_data

    def _before(self, event, context):
        try:
            self.response = None
            set_cold_start(init_timestamp_ns)

            if not should_use_extension:
                from datadog_lambda.metric import submit_invocations_metric

                submit_invocations_metric(context)

            self.trigger_tags = extract_trigger_tags(event, context)
            # Extract Datadog trace context and source from incoming requests
            dd_context, trace_context_source, event_source = extract_dd_trace_context(
                event,
                context,
                extractor=self.trace_extractor,
                decode_authorizer_context=config.decode_authorizer_context,
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

            if config.trace_enabled:
                set_dd_trace_py_root(trace_context_source, config.merge_xray_traces)
                if config.make_inferred_span:
                    self.inferred_span = create_inferred_span(
                        event, context, event_source, config.decode_authorizer_context
                    )
                if config.data_streams_enabled:
                    set_dsm_context(event, event_source)
                self.span = create_function_execution_span(
                    context=context,
                    function_name=config.function_name,
                    is_cold_start=is_cold_start(),
                    is_proactive_init=is_proactive_init(),
                    trace_context_source=trace_context_source,
                    merge_xray_traces=config.merge_xray_traces,
                    trigger_tags=self.trigger_tags,
                    parent_span=self.inferred_span,
                    span_pointers=calculate_span_pointers(event_source, event),
                )
            else:
                set_correlation_ids()
            if config.profiling_enabled and is_new_sandbox():
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
            should_trace_cold_start = config.cold_start_tracing and is_new_sandbox()
            if should_trace_cold_start:
                trace_ctx = tracer.current_trace_context()

            if self.span:
                if config.capture_payload_enabled:
                    tag_object(self.span, "function.request", event)
                    tag_object(self.span, "function.response", self.response)

                if status_code:
                    self.span.set_tag("http.status_code", status_code)
                self.span.finish()

            if self.inferred_span:
                if status_code:
                    self.inferred_span.set_tag("http.status_code", status_code)

                if config.service:
                    self.inferred_span.set_tag("peer.service", config.service)

                if InferredSpanInfo.is_async(self.inferred_span) and self.span:
                    self.inferred_span.finish(finish_time=self.span.start)
                else:
                    self.inferred_span.finish()

            if should_trace_cold_start:
                try:
                    following_span = self.span or self.inferred_span
                    ColdStartTracer(
                        tracer,
                        config.function_name,
                        following_span.start_ns,
                        trace_ctx,
                        config.min_cold_start_trace_duration,
                        config.cold_start_trace_skip_lib,
                    ).trace()
                except Exception as e:
                    logger.debug("Failed to create cold start spans. %s", e)

            if not config.flush_to_log or should_use_extension:
                from datadog_lambda.metric import flush_stats

                flush_stats(context)
            if should_use_extension and config.local_test:
                # when testing locally, the extension does not know when an
                # invocation completes because it does not have access to the
                # logs api
                flush_extension()

            if config.llmobs_enabled:
                LLMObs.flush()

            # Flush exception replay
            if config.exception_replay_enabled:
                LogsIntakeUploaderV1._instance.periodic()

            if config.encode_authorizer_context and is_authorizer_response(
                self.response
            ):
                self._inject_authorizer_span_headers(
                    event.get("requestContext", {}).get("requestId")
                )
            logger.debug("datadog_lambda_wrapper _after() done")
        except Exception as e:
            logger.error(format_err_with_traceback(e))


def format_err_with_traceback(e):
    tb = traceback.format_exc().replace("\n", "\r")
    return f"Error {e}. Traceback: {tb}"


datadog_lambda_wrapper = _LambdaDecorator
