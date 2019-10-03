# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import logging

from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core.lambda_launcher import LambdaContext

from ddtrace import patch, tracer
from datadog_lambda.constants import (
    SamplingPriority,
    TraceHeader,
    XraySubsegment,
)

logger = logging.getLogger(__name__)

dd_trace_context = {}


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
    return str(SamplingPriority.USER_KEEP) if xray_sampled \
        else str(SamplingPriority.USER_REJECT)


def extract_dd_trace_context(event):
    """
    Extract Datadog trace context from the Lambda `event` object.

    Write the context to a global `dd_trace_context`, so the trace
    can be continued on the outgoing requests with the context injected.

    Save the context to an X-Ray subsegment's metadata field, so the X-Ray
    trace can be converted to a Datadog trace in the Datadog backend with
    the correct context.
    """
    global dd_trace_context
    headers = event.get('headers', {})
    lowercase_headers = {k.lower(): v for k, v in headers.items()}

    trace_id = lowercase_headers.get(TraceHeader.TRACE_ID)
    parent_id = lowercase_headers.get(TraceHeader.PARENT_ID)
    sampling_priority = lowercase_headers.get(TraceHeader.SAMPLING_PRIORITY)
    if trace_id and parent_id and sampling_priority:
        logger.debug('Extracted Datadog trace context from headers')
        dd_trace_context = {
            'trace-id': trace_id,
            'parent-id': parent_id,
            'sampling-priority': sampling_priority,
        }
        xray_recorder.begin_subsegment(XraySubsegment.NAME)
        subsegment = xray_recorder.current_subsegment()
        subsegment.put_metadata(
            XraySubsegment.KEY,
            dd_trace_context,
            XraySubsegment.NAMESPACE
        )
        xray_recorder.end_subsegment()
    else:
        # AWS Lambda runtime caches global variables between invocations,
        # reset to avoid using the context from the last invocation.
        dd_trace_context = {}

    logger.debug('extracted dd trace context %s', dd_trace_context)


def get_dd_trace_context():
    """
    Return the Datadog trace context to be propogated on the outgoing requests.

    If the Lambda function is invoked by a Datadog-traced service, a Datadog
    trace context may already exist, and it should be used. Otherwise, use the
    current X-Ray trace entity.

    Most of widely-used HTTP clients are patched to inject the context
    automatically, but this function can be used to manually inject the trace
    context to an outgoing request.
    """
    if not is_lambda_context():
        logger.debug('get_dd_trace_context is only supported in LambdaContext')
        return {}

    global dd_trace_context
    xray_trace_entity = xray_recorder.get_trace_entity()  # xray (sub)segment
    if dd_trace_context:
        return {
            TraceHeader.TRACE_ID:
                dd_trace_context['trace-id'],
            TraceHeader.PARENT_ID: _convert_xray_entity_id(
                xray_trace_entity.id),
            TraceHeader.SAMPLING_PRIORITY:
                dd_trace_context['sampling-priority'],
        }
    else:
        return {
            TraceHeader.TRACE_ID: _convert_xray_trace_id(
                xray_trace_entity.trace_id),
            TraceHeader.PARENT_ID: _convert_xray_entity_id(
                xray_trace_entity.id),
            TraceHeader.SAMPLING_PRIORITY: _convert_xray_sampling(
                xray_trace_entity.sampled),
        }


def set_correlation_ids():
    """
    Create a dummy span, and overrides its trace_id and span_id, to make
    ddtrace.helpers.get_correlation_ids() return the correct ids for both
    auto and manual log correlations.

    TODO: Remove me when Datadog tracer is natively supported in Lambda.
    """
    if not is_lambda_context():
        logger.debug('set_correlation_ids is only supported in LambdaContext')
        return

    context = get_dd_trace_context()

    span = tracer.trace('dummy.span')
    span.trace_id = context[TraceHeader.TRACE_ID]
    span.span_id = context[TraceHeader.PARENT_ID]

    logger.debug('correlation ids set')


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
        if handler.__class__.__name__ == 'LambdaLoggerHandler':
            handler.setFormatter(logging.Formatter(
                '[%(levelname)s]\t%(asctime)s.%(msecs)dZ\t%(aws_request_id)s\t'
                '[dd.trace_id=%(dd.trace_id)s dd.span_id=%(dd.span_id)s]\t%(message)s\n',
                '%Y-%m-%dT%H:%M:%S'
            ))

    # Patch `logging.Logger.makeRecord` to actually inject correlation ids
    patch(logging=True)

    logger.debug('logs injection configured')


def is_lambda_context():
    """
    Return True if the X-Ray context is `LambdaContext`, rather than the
    regular `Context` (e.g., when testing lambda functions locally).
    """
    return type(xray_recorder.context) == LambdaContext
