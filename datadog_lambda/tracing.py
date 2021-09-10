# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import logging
import os
import json
from enum import Enum

from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core.lambda_launcher import LambdaContext
from datadog_lambda.constants import (
    SamplingPriority,
    TraceHeader,
    XraySubsegment,
    TraceContextSource,
)
from ddtrace import tracer, patch
from ddtrace import __version__ as ddtrace_version
from ddtrace.propagation.http import HTTPPropagator
from datadog_lambda import __version__ as datadog_lambda_version

logger = logging.getLogger(__name__)

dd_trace_context = {}
dd_tracing_enabled = os.environ.get("DD_TRACE_ENABLED", "false").lower() == "true"

propagator = HTTPPropagator()


class ManagedService(Enum):
    UNKNOWN = 0
    API_GATEWAY = 1
    API_GATEWAY_WEBSOCKET = 2
    HTTP_API = 3
    APPSYNC = 4


def _convert_xray_trace_id(xray_trace_id):
    """
    Convert X-Ray trace id (hex)'s last 63 bits to a Datadog trace id (int).
    """
    return str(0x7FFFFFFFFFFFFFFF & int(xray_trace_id[-16:], 16))


def _convert_xray_entity_id(xray_entity_id):
    """
    Convert X-Ray (sub)segement id (hex) to a Datadog span id (int).
    """
    return str(int(xray_entity_id, 16))


def _convert_xray_sampling(xray_sampled):
    """
    Convert X-Ray sampled (True/False) to its Datadog counterpart.
    """
    return (
        str(SamplingPriority.USER_KEEP)
        if xray_sampled
        else str(SamplingPriority.USER_REJECT)
    )


def _get_xray_trace_context():
    if not is_lambda_context():
        return None

    xray_trace_entity = xray_recorder.get_trace_entity()  # xray (sub)segment
    trace_context = {
        "trace-id": _convert_xray_trace_id(xray_trace_entity.trace_id),
        "parent-id": _convert_xray_entity_id(xray_trace_entity.id),
        "sampling-priority": _convert_xray_sampling(xray_trace_entity.sampled),
    }
    logger.debug(
        "Converted trace context %s from X-Ray segment %s",
        trace_context,
        (xray_trace_entity.trace_id, xray_trace_entity.id, xray_trace_entity.sampled),
    )
    return trace_context


def _get_dd_trace_py_context():
    span = tracer.current_span()
    if not span:
        return None

    parent_id = span.context.span_id
    trace_id = span.context.trace_id
    sampling_priority = span.context.sampling_priority
    logger.debug(
        "found dd trace context: %s", (span.context.trace_id, span.context.span_id)
    )
    return {
        "parent-id": str(parent_id),
        "trace-id": str(trace_id),
        "sampling-priority": str(sampling_priority),
        "source": TraceContextSource.DDTRACE,
    }


def _context_obj_to_headers(obj):
    return {
        TraceHeader.TRACE_ID: str(obj.get("trace-id")),
        TraceHeader.PARENT_ID: str(obj.get("parent-id")),
        TraceHeader.SAMPLING_PRIORITY: str(obj.get("sampling-priority")),
    }


def create_dd_dummy_metadata_subsegment(
    subsegment_metadata_value, subsegment_metadata_key
):
    """
    Create a Datadog subsegment to pass the Datadog trace context or Lambda function
    tags into its metadata field, so the X-Ray trace can be converted to a Datadog
    trace in the Datadog backend with the correct context.
    """
    try:
        xray_recorder.begin_subsegment(XraySubsegment.NAME)
        subsegment = xray_recorder.current_subsegment()
        subsegment.put_metadata(
            subsegment_metadata_key, subsegment_metadata_value, XraySubsegment.NAMESPACE
        )
        xray_recorder.end_subsegment()
    except Exception as e:
        logger.debug(
            "failed to create dd dummy metadata subsegment with error %s",
            e,
            exc_info=True,
        )


def extract_context_from_lambda_context(lambda_context):
    """
    Extract Datadog trace context from the `client_context` attr
    from the Lambda `context` object.

    dd_trace libraries inject this trace context on synchronous invocations
    """
    client_context = lambda_context.client_context
    trace_id = None
    parent_id = None
    sampling_priority = None
    if client_context and client_context.custom:
        if "_datadog" in client_context.custom:
            # Legacy trace propagation dict
            dd_data = client_context.custom.get("_datadog", {})
            trace_id = dd_data.get(TraceHeader.TRACE_ID)
            parent_id = dd_data.get(TraceHeader.PARENT_ID)
            sampling_priority = dd_data.get(TraceHeader.SAMPLING_PRIORITY)
        elif (
            TraceHeader.TRACE_ID in client_context.custom
            and TraceHeader.PARENT_ID in client_context.custom
            and TraceHeader.SAMPLING_PRIORITY in client_context.custom
        ):
            # New trace propagation keys
            trace_id = client_context.custom.get(TraceHeader.TRACE_ID)
            parent_id = client_context.custom.get(TraceHeader.PARENT_ID)
            sampling_priority = client_context.custom.get(TraceHeader.SAMPLING_PRIORITY)

    return trace_id, parent_id, sampling_priority


def extract_context_from_http_event_or_context(event, lambda_context):
    """
    Extract Datadog trace context from the `headers` key in from the Lambda
    `event` object.

    Falls back to lambda context if no trace data is found in the `headers`
    """
    headers = event.get("headers", {})
    lowercase_headers = {k.lower(): v for k, v in headers.items()}

    trace_id = lowercase_headers.get(TraceHeader.TRACE_ID)
    parent_id = lowercase_headers.get(TraceHeader.PARENT_ID)
    sampling_priority = lowercase_headers.get(TraceHeader.SAMPLING_PRIORITY)

    if not trace_id or not parent_id or not sampling_priority:
        return extract_context_from_lambda_context(lambda_context)

    return trace_id, parent_id, sampling_priority


def extract_context_from_sqs_event_or_context(event, lambda_context):
    """
    Extract Datadog trace context from the first SQS message attributes.

    Falls back to lambda context if no trace data is found in the SQS message attributes.
    """
    try:
        first_record = event["Records"][0]
        msg_attributes = first_record.get("messageAttributes", {})
        dd_json_data = msg_attributes.get("_datadog", {}).get("stringValue", r"{}")
        dd_data = json.loads(dd_json_data)
        trace_id = dd_data.get(TraceHeader.TRACE_ID)
        parent_id = dd_data.get(TraceHeader.PARENT_ID)
        sampling_priority = dd_data.get(TraceHeader.SAMPLING_PRIORITY)

        return trace_id, parent_id, sampling_priority
    except Exception:
        return extract_context_from_lambda_context(lambda_context)


def extract_context_custom_extractor(extractor, event, lambda_context):
    """
    Extract Datadog trace context using a custom trace extractor function
    """
    try:
        (
            trace_id,
            parent_id,
            sampling_priority,
        ) = extractor(event, lambda_context)
        return trace_id, parent_id, sampling_priority
    except Exception as e:
        logger.debug("The trace extractor returned with error %s", e)

        return None, None, None


def extract_dd_trace_context(event, lambda_context, extractor=None):
    """
    Extract Datadog trace context from the Lambda `event` object.

    Write the context to a global `dd_trace_context`, so the trace
    can be continued on the outgoing requests with the context injected.
    """
    global dd_trace_context
    trace_context_source = None

    if extractor is not None:
        (
            trace_id,
            parent_id,
            sampling_priority,
        ) = extract_context_custom_extractor(extractor, event, lambda_context)
    elif "headers" in event:
        (
            trace_id,
            parent_id,
            sampling_priority,
        ) = extract_context_from_http_event_or_context(event, lambda_context)
    elif "Records" in event:
        (
            trace_id,
            parent_id,
            sampling_priority,
        ) = extract_context_from_sqs_event_or_context(event, lambda_context)
    else:
        trace_id, parent_id, sampling_priority = extract_context_from_lambda_context(
            lambda_context
        )

    if trace_id and parent_id and sampling_priority:
        logger.debug("Extracted Datadog trace context from event or context")
        metadata = {
            "trace-id": trace_id,
            "parent-id": parent_id,
            "sampling-priority": sampling_priority,
        }
        dd_trace_context = metadata.copy()
        trace_context_source = TraceContextSource.EVENT
    else:
        # AWS Lambda runtime caches global variables between invocations,
        # reset to avoid using the context from the last invocation.
        dd_trace_context = _get_xray_trace_context()
        if dd_trace_context:
            trace_context_source = TraceContextSource.XRAY
    logger.debug("extracted dd trace context %s", dd_trace_context)
    return dd_trace_context, trace_context_source


def get_dd_trace_context():
    """
    Return the Datadog trace context to be propogated on the outgoing requests.

    If the Lambda function is invoked by a Datadog-traced service, a Datadog
    trace context may already exist, and it should be used. Otherwise, use the
    current X-Ray trace entity, or the dd-trace-py context if DD_TRACE_ENABLED is true.

    Most of widely-used HTTP clients are patched to inject the context
    automatically, but this function can be used to manually inject the trace
    context to an outgoing request.
    """
    global dd_trace_context

    context = None
    xray_context = None

    try:
        xray_context = _get_xray_trace_context()  # xray (sub)segment
    except Exception as e:
        logger.debug(
            "get_dd_trace_context couldn't read from segment from x-ray, with error %s"
            % e
        )

    if xray_context and not dd_trace_context:
        context = xray_context
    elif xray_context and dd_trace_context:
        context = dd_trace_context.copy()
        context["parent-id"] = xray_context["parent-id"]
        logger.debug("Set parent id from xray trace context: %s", context["parent-id"])

    if dd_tracing_enabled:
        dd_trace_py_context = _get_dd_trace_py_context()
        if dd_trace_py_context is not None:
            context = dd_trace_py_context

    return _context_obj_to_headers(context) if context is not None else {}


def set_correlation_ids():
    """
    Create a dummy span, and overrides its trace_id and span_id, to make
    ddtrace.helpers.get_correlation_ids() return the correct ids for both
    auto and manual log correlations.

    TODO: Remove me when Datadog tracer is natively supported in Lambda.
    """
    if not is_lambda_context():
        logger.debug("set_correlation_ids is only supported in LambdaContext")
        return
    if dd_tracing_enabled:
        logger.debug("using ddtrace implementation for spans")
        return

    context = get_dd_trace_context()

    span = tracer.trace("dummy.span")
    span.trace_id = int(context[TraceHeader.TRACE_ID])
    span.span_id = int(context[TraceHeader.PARENT_ID])

    logger.debug("correlation ids set")


def inject_correlation_ids():
    """
    Override the formatter of LambdaLoggerHandler to inject datadog trace and
    span id for log correlation.

    For manual injections to custom log handlers, use `ddtrace.helpers.get_correlation_ids`
    to retrieve correlation ids (trace_id, span_id).
    """
    # Override the log format of the AWS provided LambdaLoggerHandler
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if (
            handler.__class__.__name__ == "LambdaLoggerHandler"
            and type(handler.formatter) == logging.Formatter
        ):
            handler.setFormatter(
                logging.Formatter(
                    "[%(levelname)s]\t%(asctime)s.%(msecs)dZ\t%(aws_request_id)s\t"
                    "[dd.trace_id=%(dd.trace_id)s dd.span_id=%(dd.span_id)s]\t%(message)s\n",
                    "%Y-%m-%dT%H:%M:%S",
                )
            )

    # Patch `logging.Logger.makeRecord` to actually inject correlation ids
    patch(logging=True)

    logger.debug("logs injection configured")


def is_lambda_context():
    """
    Return True if the X-Ray context is `LambdaContext`, rather than the
    regular `Context` (e.g., when testing lambda functions locally).
    """
    return type(xray_recorder.context) == LambdaContext


def set_dd_trace_py_root(trace_context_source, merge_xray_traces):
    if trace_context_source == TraceContextSource.EVENT or merge_xray_traces:
        headers = _context_obj_to_headers(dd_trace_context)
        span_context = propagator.extract(headers)
        tracer.context_provider.activate(span_context)
        logger.debug(
            "Set dd trace root context to: %s",
            (span_context.trace_id, span_context.span_id),
        )


def create_inferred_span(event, context, function_name):
    managed_service = detect_inferrable_span_type(event)
    if managed_service == ManagedService.API_GATEWAY:
        logger.debug("API Gateway event detected. Inferring a span")
        return create_inferred_span_from_api_gateway_event(
            event, context, function_name
        )
    elif managed_service == ManagedService.HTTP_API:
        logger.debug("HTTP API event detected. Inferring a span")
        return create_inferred_span_from_http_api_event(event, context, function_name)
    elif managed_service == ManagedService.API_GATEWAY_WEBSOCKET:
        logger.debug("API Gateway Websocket event detected. Inferring a span")
        return create_inferred_span_from_api_gateway_websocket_event(
            event, context, function_name
        )
    elif managed_service == ManagedService.UNKNOWN:
        logger.debug("Unable to infer a span: unknown event type")
        return None


def detect_inferrable_span_type(event):
    if "httpMethod" in event:  # likely some kind of API Gateway event
        return ManagedService.API_GATEWAY
    if "routeKey" in event:  # likely HTTP API
        return ManagedService.HTTP_API
    if (
        "requestContext" in event and "messageDirection" in event["requestContext"]
    ):  # likely a websocket API
        return ManagedService.API_GATEWAY_WEBSOCKET
    return ManagedService.UNKNOWN


def create_inferred_span_from_api_gateway_websocket_event(
    event, context, function_name
):
    tags = {
        "operation_name": "aws.apigateway.websocket",
        "service_name": event["requestContext"]["domainName"]
        + event["requestContext"]["routeKey"],
        "url": event["requestContext"]["domainName"],
        "endpoint": event["requestContext"]["routeKey"],
        "resource_names": function_name,
        "request_id": context.aws_request_id,
        "connection_id": event["requestContext"]["connectionId"],
    }
    request_time_epoch = event["requestContext"]["requestTimeEpoch"]
    args = {
        "service": "aws.apigateway.websocket",
        "resource": function_name,
        "span_type": "serverless",
    }
    tracer.set_tags({"_dd.origin": "lambda"})
    span = tracer.trace("aws.lambda", **args)
    if span:
        span.set_tags(tags)
    span.start = request_time_epoch / 1000
    return span


def create_inferred_span_from_api_gateway_event(event, context, function_name):
    tags = {
        "operation_name": "aws.apigateway",
        "service_name": event["requestContext"]["domainName"] + event["path"],
        "url": event["requestContext"]["domainName"],
        "endpoint": event["path"],
        "http.method": event["httpMethod"],
        "resource_names": function_name,
        "request_id": context.aws_request_id,
    }

    request_time_epoch = event["requestContext"]["requestTimeEpoch"]
    args = {
        "service": "aws.apigateway",
        "resource": function_name,
        "span_type": "serverless",
    }
    tracer.set_tags({"_dd.origin": "lambda"})
    span = tracer.trace("aws.lambda", **args)
    if span:
        span.set_tags(tags)
    span.start = request_time_epoch / 1000
    return span


def create_inferred_span_from_http_api_event(event, context, function_name):
    tags = {
        "operation_name": "aws.httpapi",
        "service_name": event["requestContext"]["domainName"] + event["rawPath"],
        "url": event["requestContext"]["domainName"],
        "endpoint": event["rawPath"],
        "http.method": event["requestContext"]["http"]["method"],
        "resource_names": function_name,
        "request_id": context.aws_request_id,
    }
    request_time_epoch = event["requestContext"]["timeEpoch"]
    args = {
        "service": "aws.httpapi",
        "resource": function_name,
        "span_type": "serverless",
    }
    tracer.set_tags({"_dd.origin": "lambda"})
    span = tracer.trace("aws.lambda", **args)
    if span:
        span.set_tags(tags)
    span.start = request_time_epoch / 1000
    return span


def create_function_execution_span(
    context,
    function_name,
    is_cold_start,
    trace_context_source,
    merge_xray_traces,
    trigger_tags,
    upstream=None,
):
    tags = {}
    if context:
        function_arn = (context.invoked_function_arn or "").lower()
        tk = function_arn.split(":")
        function_arn = ":".join(tk[0:7]) if len(tk) > 7 else function_arn
        function_version = tk[7] if len(tk) > 7 else "$LATEST"
        tags = {
            "cold_start": str(is_cold_start).lower(),
            "function_arn": function_arn,
            "function_version": function_version,
            "request_id": context.aws_request_id,
            "resource_names": context.function_name,
            "functionname": context.function_name.lower()
            if context.function_name
            else None,
            "datadog_lambda": datadog_lambda_version,
            "dd_trace": ddtrace_version,
        }
    if trace_context_source == TraceContextSource.XRAY and merge_xray_traces:
        tags["_dd.parent_source"] = trace_context_source
    tags.update(trigger_tags)
    args = {
        "service": "aws.lambda",
        "resource": function_name,
        "span_type": "serverless",
    }
    tracer.set_tags({"_dd.origin": "lambda"})
    span = tracer.trace("aws.lambda", **args)
    if span:
        span.set_tags(tags)
    if upstream:
        span.parent_id = upstream.span_id
    return span
