# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

from aws_xray_sdk.core import xray_recorder

from datadog_lambda.constants import (
    SamplingPriority,
    TraceHeader,
    XraySubsegment,
)

dd_trace_context = {}


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
    trace_id = headers.get(TraceHeader.TRACE_ID)
    parent_id = headers.get(TraceHeader.PARENT_ID)
    sampling_priority = headers.get(TraceHeader.SAMPLING_PRIORITY)
    if trace_id and parent_id and sampling_priority:
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
