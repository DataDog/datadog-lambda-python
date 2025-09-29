# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.
import logging
import os
import re
import traceback
import ujson as json
from datetime import datetime, timezone
from typing import Optional, Dict

from datadog_lambda.metric import submit_errors_metric

try:
    from typing import Literal
except ImportError:
    # Literal was added to typing in python 3.8
    from typing_extensions import Literal

from datadog_lambda.constants import (
    SamplingPriority,
    TraceContextSource,
    XrayDaemon,
    Headers,
)
from datadog_lambda.xray import (
    send_segment,
    parse_xray_header,
)

from ddtrace import patch
from ddtrace import __version__ as ddtrace_version
from ddtrace.propagation.http import HTTPPropagator
from ddtrace.trace import Context, Span, tracer

from datadog_lambda.config import config
from datadog_lambda import __version__ as datadog_lambda_version
from datadog_lambda.trigger import (
    _EventSource,
    parse_event_source,
    get_first_record,
    is_step_function_event,
    EventTypes,
    EventSubtypes,
)

if config.otel_enabled:
    from opentelemetry.trace import set_tracer_provider
    from ddtrace.opentelemetry import TracerProvider

    set_tracer_provider(TracerProvider())


logger = logging.getLogger(__name__)

dd_trace_context = None
if config.telemetry_enabled:
    # Enable the telemetry client if the user has opted in
    from ddtrace.internal.telemetry import telemetry_writer

    telemetry_writer.enable()

propagator = HTTPPropagator()

DD_TRACE_JAVA_TRACE_ID_PADDING = "00000000"
HIGHER_64_BITS = "HIGHER_64_BITS"
LOWER_64_BITS = "LOWER_64_BITS"


def _dsm_set_checkpoint(context_json, event_type, arn):
    if not config.data_streams_enabled:
        return

    if not arn:
        return

    try:
        from ddtrace.data_streams import set_consume_checkpoint

        carrier_get = lambda k: context_json and context_json.get(k)  # noqa: E731
        set_consume_checkpoint(event_type, arn, carrier_get, manual_checkpoint=False)
    except Exception as e:
        logger.debug(
            f"DSM:Failed to set consume checkpoint for {event_type} {arn}: {e}"
        )


def _convert_xray_trace_id(xray_trace_id):
    """
    Convert X-Ray trace id (hex)'s last 63 bits to a Datadog trace id (int).
    """
    return 0x7FFFFFFFFFFFFFFF & int(xray_trace_id[-16:], 16)


def _convert_xray_entity_id(xray_entity_id):
    """
    Convert X-Ray (sub)segement id (hex) to a Datadog span id (int).
    """
    return int(xray_entity_id, 16)


def _convert_xray_sampling(xray_sampled):
    """
    Convert X-Ray sampled (True/False) to its Datadog counterpart.
    """
    return SamplingPriority.USER_KEEP if xray_sampled else SamplingPriority.USER_REJECT


def _get_xray_trace_context():
    if not config.is_lambda_context:
        return None

    xray_trace_entity = parse_xray_header(
        os.environ.get(XrayDaemon.XRAY_TRACE_ID_HEADER_NAME, "")
    )
    if xray_trace_entity is None:
        return None
    trace_context = Context(
        trace_id=_convert_xray_trace_id(xray_trace_entity.get("trace_id")),
        span_id=_convert_xray_entity_id(xray_trace_entity.get("parent_id")),
        sampling_priority=_convert_xray_sampling(xray_trace_entity.get("sampled")),
    )
    logger.debug(
        "Converted trace context %s from X-Ray segment %s",
        trace_context,
        xray_trace_entity,
    )
    return trace_context


def _get_dd_trace_py_context():
    span = tracer.current_span()
    if not span:
        return None

    logger.debug(
        "found dd trace context: trace_id=%s span_id=%s",
        span.context.trace_id,
        span.context.span_id,
    )
    return span.context


def _is_context_complete(context):
    return (
        context
        and context.trace_id
        and context.span_id
        and context.sampling_priority is not None
    )


def create_dd_dummy_metadata_subsegment(
    subsegment_metadata_value, subsegment_metadata_key
):
    """
    Create a Datadog subsegment to pass the Datadog trace context or Lambda function
    tags into its metadata field, so the X-Ray trace can be converted to a Datadog
    trace in the Datadog backend with the correct context.
    """
    send_segment(subsegment_metadata_key, subsegment_metadata_value)


def extract_context_from_lambda_context(lambda_context):
    """
    Extract Datadog trace context from the `client_context` attr
    from the Lambda `context` object.

    dd_trace libraries inject this trace context on synchronous invocations
    """
    dd_data = None
    client_context = lambda_context.client_context
    if client_context and client_context.custom:
        dd_data = client_context.custom
        if "_datadog" in client_context.custom:
            # Legacy trace propagation dict
            dd_data = client_context.custom.get("_datadog")
    return propagator.extract(dd_data)


def extract_context_from_http_event_or_context(
    event,
    lambda_context,
    event_source: _EventSource,
    decode_authorizer_context: bool = True,
):
    """
    Extract Datadog trace context from the `headers` key in from the Lambda
    `event` object.

    Falls back to lambda context if no trace data is found in the `headers`
    """
    if decode_authorizer_context:
        is_http_api = event_source.equals(
            EventTypes.API_GATEWAY, subtype=EventSubtypes.HTTP_API
        )
        injected_authorizer_data = get_injected_authorizer_data(event, is_http_api)
        context = propagator.extract(injected_authorizer_data)
        if _is_context_complete(context):
            return context

    headers = event.get("headers")
    context = propagator.extract(headers)

    if not _is_context_complete(context):
        return extract_context_from_lambda_context(lambda_context)

    return context


# def extract_context_from_request_header_or_context(event, lambda_context, event_source):
#     request = event.get("request")
#     if isinstance(request, (set, dict)) and "headers" in request:
#         context = extract_context_from_http_event_or_context(
#             request,
#             lambda_context,
#             event_source,
#             decode_authorizer_context=False,
#         )
#     else:
#         context = extract_context_from_lambda_context(lambda_context)
#     return context


def create_sns_event(message):
    return {
        "Records": [
            {
                "EventSource": "aws:sns",
                "EventVersion": "1.0",
                "Sns": message,
            }
        ]
    }


def extract_context_from_sqs_or_sns_event_or_context(
    event, lambda_context, event_source
):
    """
    Extract Datadog trace context from an SQS event.

    The extraction chain goes as follows:
    EB => SQS (First records body contains EB context), or
    SNS => SQS (First records body contains SNS context), or
    SQS or SNS (`messageAttributes` for SQS context,
                `MessageAttributes` for SNS context), else
    Lambda Context.

    Falls back to lambda context if no trace data is found in the SQS message attributes.
    Set a DSM checkpoint if DSM is enabled and the method for context propagation is supported.
    """
    source_arn = ""
    event_type = "sqs" if event_source.equals(EventTypes.SQS) else "sns"

    # EventBridge => SQS
    try:
        context = _extract_context_from_eventbridge_sqs_event(event)
        if _is_context_complete(context):
            return context
    except Exception:
        logger.debug("Failed extracting context as EventBridge to SQS.")

    try:
        first_record = event.get("Records")[0]
        source_arn = first_record.get("eventSourceARN", "")

        # logic to deal with SNS => SQS event
        if "body" in first_record:
            body_str = first_record.get("body")
            try:
                body = json.loads(body_str)
                if body.get("Type", "") == "Notification" and "TopicArn" in body:
                    logger.debug("Found SNS message inside SQS event")
                    first_record = get_first_record(create_sns_event(body))
            except Exception:
                pass

        msg_attributes = first_record.get("messageAttributes")
        if msg_attributes is None:
            sns_record = first_record.get("Sns") or {}
            # SNS->SQS event would extract SNS arn without this check
            if event_source.equals(EventTypes.SNS):
                source_arn = sns_record.get("TopicArn", "")
            msg_attributes = sns_record.get("MessageAttributes") or {}
        dd_payload = msg_attributes.get("_datadog")
        if dd_payload:
            # SQS uses dataType and binaryValue/stringValue
            # SNS uses Type and Value
            dd_json_data = None
            dd_json_data_type = dd_payload.get("Type") or dd_payload.get("dataType")
            if dd_json_data_type == "Binary":
                import base64

                dd_json_data = dd_payload.get("binaryValue") or dd_payload.get("Value")
                if dd_json_data:
                    dd_json_data = base64.b64decode(dd_json_data)
            elif dd_json_data_type == "String":
                dd_json_data = dd_payload.get("stringValue") or dd_payload.get("Value")
            else:
                logger.debug(
                    "Datadog Lambda Python only supports extracting trace"
                    "context from String or Binary SQS/SNS message attributes"
                )

            if dd_json_data:
                dd_data = json.loads(dd_json_data)

                if is_step_function_event(dd_data):
                    try:
                        return extract_context_from_step_functions(dd_data, None)
                    except Exception:
                        logger.debug(
                            "Failed to extract Step Functions context from SQS/SNS event."
                        )
                context = propagator.extract(dd_data)
                _dsm_set_checkpoint(dd_data, event_type, source_arn)
                return context
        else:
            # Handle case where trace context is injected into attributes.AWSTraceHeader
            # example: Root=1-654321ab-000000001234567890abcdef;Parent=0123456789abcdef;Sampled=1
            attrs = event.get("Records")[0].get("attributes")
            if attrs:
                x_ray_header = attrs.get("AWSTraceHeader")
                if x_ray_header:
                    x_ray_context = parse_xray_header(x_ray_header)
                    trace_id_parts = x_ray_context.get("trace_id", "").split("-")
                    if len(trace_id_parts) > 2 and trace_id_parts[2].startswith(
                        DD_TRACE_JAVA_TRACE_ID_PADDING
                    ):
                        # If it starts with eight 0's padding,
                        # then this AWSTraceHeader contains Datadog injected trace context
                        logger.debug(
                            "Found dd-trace injected trace context from AWSTraceHeader"
                        )
                        return Context(
                            trace_id=int(trace_id_parts[2][8:], 16),
                            span_id=int(x_ray_context["parent_id"], 16),
                            sampling_priority=float(x_ray_context["sampled"]),
                        )
        # Still want to set a DSM checkpoint even if DSM context not propagated
        _dsm_set_checkpoint(None, event_type, source_arn)
        return extract_context_from_lambda_context(lambda_context)
    except Exception as e:
        logger.debug("The trace extractor returned with error %s", e)
        # Still want to set a DSM checkpoint even if DSM context not propagated
        _dsm_set_checkpoint(None, event_type, source_arn)
        return extract_context_from_lambda_context(lambda_context)


def _extract_context_from_eventbridge_sqs_event(event):
    """
    Extracts Datadog trace context from an SQS event triggered by
    EventBridge.

    This is only possible if first record in `Records` contains a
    `body` field which contains the EventBridge `detail` as a JSON string.
    """
    first_record = event.get("Records")[0]
    body_str = first_record.get("body")
    body = json.loads(body_str)
    detail = body.get("detail")
    dd_context = detail.get("_datadog")

    if is_step_function_event(dd_context):
        try:
            return extract_context_from_step_functions(dd_context, None)
        except Exception:
            logger.debug(
                "Failed to extract Step Functions context from EventBridge to SQS event."
            )

    return propagator.extract(dd_context)


def extract_context_from_eventbridge_event(event, lambda_context):
    """
    Extract datadog trace context from an EventBridge message's Details.
    This is only possible if Details is a JSON string.

    If we find a Step Function context, try to extract the trace context from
    that header.
    """
    try:
        detail = event.get("detail")
        dd_context = detail.get("_datadog")
        if not dd_context:
            return extract_context_from_lambda_context(lambda_context)

        try:
            return extract_context_from_step_functions(dd_context, None)
        except Exception:
            logger.debug(
                "Failed to extract Step Functions context from EventBridge event."
            )

        return propagator.extract(dd_context)
    except Exception as e:
        logger.debug("The trace extractor returned with error %s", e)
        return extract_context_from_lambda_context(lambda_context)


def extract_context_from_kinesis_event(event, lambda_context):
    """
    Extract datadog trace context from a Kinesis Stream's base64 encoded data string
    Set a DSM checkpoint if DSM is enabled and the method for context propagation is supported.
    """
    source_arn = ""
    try:
        record = get_first_record(event)
        source_arn = record.get("eventSourceARN", "")
        kinesis = record.get("kinesis")
        if not kinesis:
            return extract_context_from_lambda_context(lambda_context)
        data = kinesis.get("data")
        if data:
            import base64

            b64_bytes = data.encode("ascii")
            str_bytes = base64.b64decode(b64_bytes)
            data_str = str_bytes.decode("ascii")
            data_obj = json.loads(data_str)
            dd_ctx = data_obj.get("_datadog")
            if dd_ctx:
                context = propagator.extract(dd_ctx)
                _dsm_set_checkpoint(dd_ctx, "kinesis", source_arn)
                return context
    except Exception as e:
        logger.debug("The trace extractor returned with error %s", e)
    # Still want to set a DSM checkpoint even if DSM context not propagated
    _dsm_set_checkpoint(None, "kinesis", source_arn)
    return extract_context_from_lambda_context(lambda_context)


def _deterministic_sha256_hash(s: str, part: str) -> int:
    import hashlib

    sha256_hash = hashlib.sha256(s.encode()).hexdigest()
    # First two chars is '0b'. zfill to ensure 256 bits, but we only care about the first 128 bits
    binary_hash = bin(int(sha256_hash, 16))[2:].zfill(256)
    if part == HIGHER_64_BITS:
        updated_binary_hash = "0" + binary_hash[1:64]
    else:
        updated_binary_hash = "0" + binary_hash[65:128]
    result = int(updated_binary_hash, 2)
    if result == 0:
        return 1
    return result


def _parse_high_64_bits(trace_tags: str) -> str:
    """
    Parse a list of trace tags such as [_dd.p.tid=66bcb5eb00000000,_dd.p.dm=-0] and return the
    value of the _dd.p.tid tag or an empty string if not found.
    """
    if trace_tags:
        for tag in trace_tags.split(","):
            if "_dd.p.tid=" in tag:
                return tag.split("=")[1]

    return ""


def _generate_sfn_parent_id(context: dict) -> int:
    """
    Generates a stable parent span ID for a downstream Lambda invoked by a Step Function. The
    upstream Step Function execution context is used to infer the parent's span ID, ensuring trace
    continuity.

    `RetryCount` and `RedriveCount` are appended only when both are nonzero to maintain
    compatibility with older Lambda layers that did not include these fields.
    """
    execution_id = context.get("Execution").get("Id")
    redrive_count = context.get("Execution").get("RedriveCount", 0)
    state_name = context.get("State").get("Name")
    state_entered_time = context.get("State").get("EnteredTime")
    retry_count = context.get("State").get("RetryCount", 0)

    include_counts = not (retry_count == 0 and redrive_count == 0)
    counts_suffix = f"#{retry_count}#{redrive_count}" if include_counts else ""

    return _deterministic_sha256_hash(
        f"{execution_id}#{state_name}#{state_entered_time}{counts_suffix}",
        HIGHER_64_BITS,
    )


def _generate_sfn_trace_id(execution_id: str, part: str):
    """
    Take the SHA-256 hash of the execution_id to calculate the trace ID. If the high 64 bits are
    specified, we take those bits and use hex to encode it. We also remove the first two characters
    as they will be '0x in the hex string.

    We care about full 128 bits because they will break up into traditional traceID and
    _dd.p.tid tag.
    """
    if part == HIGHER_64_BITS:
        return hex(_deterministic_sha256_hash(execution_id, part))[2:]
    return _deterministic_sha256_hash(execution_id, part)


def extract_context_from_step_functions(event, lambda_context):
    """
    Only extract datadog trace context when Step Functions Context Object is injected
    into lambda's event dict. Unwrap "Payload" if it exists to handle Legacy Lambda cases.

    If '_datadog' header is present, we have two cases:
      1. Root is a Lambda and we use its traceID
      2. Root is a SFN, and we use its executionARN to calculate the traceID
    We calculate the parentID the same in both cases by using the parent SFN's context object.

    Otherwise, we're dealing with the legacy case where we only have the parent SFN's context
    object.
    """
    try:
        event = event.get("Payload", event)
        event = event.get("_datadog", event)

        meta = {}

        if event.get("serverless-version") == "v1":
            if "x-datadog-trace-id" in event:  # lambda root
                trace_id = int(event.get("x-datadog-trace-id"))
                high_64_bit_trace_id = _parse_high_64_bits(event.get("x-datadog-tags"))
                if high_64_bit_trace_id:
                    meta["_dd.p.tid"] = high_64_bit_trace_id
            else:  # sfn root
                root_execution_id = event.get("RootExecutionId")
                trace_id = _generate_sfn_trace_id(root_execution_id, LOWER_64_BITS)
                meta["_dd.p.tid"] = _generate_sfn_trace_id(
                    root_execution_id, HIGHER_64_BITS
                )

            parent_id = _generate_sfn_parent_id(event)
        else:
            execution_id = event.get("Execution").get("Id")
            trace_id = _generate_sfn_trace_id(execution_id, LOWER_64_BITS)
            meta["_dd.p.tid"] = _generate_sfn_trace_id(execution_id, HIGHER_64_BITS)
            parent_id = _generate_sfn_parent_id(event)

        sampling_priority = SamplingPriority.AUTO_KEEP
        return Context(
            trace_id=trace_id,
            span_id=parent_id,
            sampling_priority=sampling_priority,
            meta=meta,
        )
    except Exception as e:
        logger.debug("The Step Functions trace extractor returned with error %s", e)
        return extract_context_from_lambda_context(lambda_context)


def extract_context_custom_extractor(extractor, event, lambda_context):
    """
    Extract Datadog trace context using a custom trace extractor function
    """
    try:
        trace_id, parent_id, sampling_priority = extractor(event, lambda_context)
        return Context(
            trace_id=int(trace_id),
            span_id=int(parent_id),
            sampling_priority=int(sampling_priority),
        )
    except Exception as e:
        logger.debug("The trace extractor returned with error %s", e)


def is_authorizer_response(response) -> bool:
    try:
        return (
            response is not None
            and response["principalId"]
            and response["policyDocument"]
        )
    except (KeyError, AttributeError):
        pass
    except Exception as e:
        logger.debug("unknown error while checking is_authorizer_response %s", e)
    return False


def get_injected_authorizer_data(event, is_http_api) -> dict:
    try:
        req_ctx = event.get("requestContext")
        if not req_ctx:
            return None
        authorizer_headers = req_ctx.get("authorizer")
        if not authorizer_headers:
            return None

        if is_http_api:
            lambda_hdr = authorizer_headers.get("lambda")
            if not lambda_hdr:
                return None
            dd_data_raw = lambda_hdr.get("_datadog")
        else:
            dd_data_raw = authorizer_headers.get("_datadog")

        if not dd_data_raw:
            return None

        import base64

        injected_data = json.loads(base64.b64decode(dd_data_raw))

        # Lambda authorizer's results can be cached. But the payload will still have the injected
        # data in cached requests. How to distinguish cached case and ignore the injected data ?
        # APIGateway automatically injects a integrationLatency data in some cases. If it's >0 we
        # know that it's not cached. But integrationLatency is not available for Http API case. In
        # that case, we use the injected Authorizing_Request_Id to tell if it's cached. But token
        # authorizers don't pass on the requestId. The Authorizing_Request_Id can't work for all
        # cases neither. As a result, we combine both methods as shown below.
        if authorizer_headers.get("integrationLatency", 0) > 0:
            return injected_data
        req_ctx = event.get("requestContext")
        if not req_ctx:
            return None
        if req_ctx.get("requestId") == injected_data.get(
            Headers.Authorizing_Request_Id
        ):
            return injected_data
        return None

    except Exception as e:
        logger.debug("Failed to check if invocated by an authorizer. error %s", e)


def extract_dd_trace_context(
    event, lambda_context, extractor=None, decode_authorizer_context: bool = True
):
    """
    Extract Datadog trace context from the Lambda `event` object.

    Write the context to a global `dd_trace_context`, so the trace
    can be continued on the outgoing requests with the context injected.
    """
    global dd_trace_context
    trace_context_source = None
    event_source = parse_event_source(event)

    if extractor is not None:
        context = extract_context_custom_extractor(extractor, event, lambda_context)
    elif isinstance(event, (set, dict)) and "request" in event:
        # context = extract_context_from_request_header_or_context(
        #     event, lambda_context, event_source
        # )
        request = event.get("request")
        if isinstance(request, (set, dict)) and "headers" in request:
            context = extract_context_from_http_event_or_context(
                request,
                lambda_context,
                event_source,
                decode_authorizer_context=False,
            )
        else:
            context = extract_context_from_lambda_context(lambda_context)
    elif isinstance(event, (set, dict)) and "headers" in event:
        context = extract_context_from_http_event_or_context(
            event, lambda_context, event_source, decode_authorizer_context
        )
    elif event_source.equals(EventTypes.SNS) or event_source.equals(EventTypes.SQS):
        context = extract_context_from_sqs_or_sns_event_or_context(
            event, lambda_context, event_source
        )
    elif event_source.equals(EventTypes.EVENTBRIDGE):
        context = extract_context_from_eventbridge_event(event, lambda_context)
    elif event_source.equals(EventTypes.KINESIS):
        context = extract_context_from_kinesis_event(event, lambda_context)
    elif event_source.equals(EventTypes.STEPFUNCTIONS):
        context = extract_context_from_step_functions(event, lambda_context)
    else:
        context = extract_context_from_lambda_context(lambda_context)

    if _is_context_complete(context):
        logger.debug("Extracted Datadog trace context from event or context")
        dd_trace_context = context
        trace_context_source = TraceContextSource.EVENT
    else:
        # AWS Lambda runtime caches global variables between invocations,
        # reset to avoid using the context from the last invocation.
        dd_trace_context = _get_xray_trace_context()
        if dd_trace_context:
            trace_context_source = TraceContextSource.XRAY
    logger.debug("extracted dd trace context %s", dd_trace_context)
    return dd_trace_context, trace_context_source, event_source


def get_dd_trace_context_obj():
    """
    Return the Datadog trace context to be propagated on the outgoing requests.

    If the Lambda function is invoked by a Datadog-traced service, a Datadog
    trace context may already exist, and it should be used. Otherwise, use the
    current X-Ray trace entity, or the dd-trace-py context if DD_TRACE_ENABLED is true.

    Most of widely-used HTTP clients are patched to inject the context
    automatically, but this function can be used to manually inject the trace
    context to an outgoing request.
    """
    if config.trace_enabled:
        dd_trace_py_context = _get_dd_trace_py_context()
        if _is_context_complete(dd_trace_py_context):
            return dd_trace_py_context

    try:
        xray_context = _get_xray_trace_context()  # xray (sub)segment
    except Exception as e:
        logger.debug(
            "get_dd_trace_context couldn't read from segment from x-ray, with error %s",
            e,
        )
    if not xray_context:
        return None

    if not _is_context_complete(dd_trace_context):
        return xray_context

    logger.debug("Set parent id from xray trace context: %s", xray_context.span_id)
    return Context(
        trace_id=dd_trace_context.trace_id,
        span_id=xray_context.span_id,
        sampling_priority=dd_trace_context.sampling_priority,
        meta=dd_trace_context._meta.copy(),
        metrics=dd_trace_context._metrics.copy(),
    )


def get_dd_trace_context():
    """
    Return the Datadog trace context to be propagated on the outgoing requests,
    as a dict of headers.
    """
    headers = {}
    context = get_dd_trace_context_obj()
    if not _is_context_complete(context):
        return headers
    propagator.inject(context, headers)
    return headers


def set_correlation_ids():
    """
    Create a dummy span, and overrides its trace_id and span_id, to make
    ddtrace.helpers.get_log_correlation_context() return a dict containing the correct ids for both
    auto and manual log correlations.

    TODO: Remove me when Datadog tracer is natively supported in Lambda.
    """
    if not config.is_lambda_context:
        logger.debug("set_correlation_ids is only supported in LambdaContext")
        return
    if config.trace_enabled:
        logger.debug("using ddtrace implementation for spans")
        return

    context = get_dd_trace_context_obj()
    if not _is_context_complete(context):
        return

    tracer.context_provider.activate(context)
    tracer.trace("dummy.span")
    logger.debug("correlation ids set")


def inject_correlation_ids():
    """
    Override the formatter of LambdaLoggerHandler to inject datadog trace and
    span id for log correlation.

    For manual injections to custom log handlers, use `ddtrace.helpers.get_log_correlation_context`
    to retrieve a dict containing correlation ids (trace_id, span_id).
    """
    # Override the log format of the AWS provided LambdaLoggerHandler
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if handler.__class__.__name__ == "LambdaLoggerHandler" and isinstance(
            handler.formatter, logging.Formatter
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


def set_dd_trace_py_root(trace_context_source, merge_xray_traces):
    if not _is_context_complete(dd_trace_context):
        return
    if trace_context_source == TraceContextSource.EVENT or merge_xray_traces:
        context = Context(
            trace_id=dd_trace_context.trace_id,
            span_id=dd_trace_context.span_id,
            sampling_priority=dd_trace_context.sampling_priority,
        )
        if merge_xray_traces:
            xray_context = _get_xray_trace_context()
            if xray_context and xray_context.span_id:
                context.span_id = xray_context.span_id

        tracer.context_provider.activate(context)
        logger.debug(
            "Set dd trace root context to: trace_id=%s span_id=%s",
            context.trace_id,
            context.span_id,
        )


def create_inferred_span(
    event,
    context,
    event_source: _EventSource = None,
    decode_authorizer_context: bool = True,
):
    if event_source is None:
        event_source = parse_event_source(event)
    try:
        if event_source.equals(
            EventTypes.API_GATEWAY, subtype=EventSubtypes.API_GATEWAY
        ):
            logger.debug("API Gateway event detected. Inferring a span")
            return create_inferred_span_from_api_gateway_event(
                event, context, decode_authorizer_context
            )
        elif event_source.equals(EventTypes.LAMBDA_FUNCTION_URL):
            logger.debug("Function URL event detected. Inferring a span")
            return create_inferred_span_from_lambda_function_url_event(event, context)
        elif event_source.equals(
            EventTypes.API_GATEWAY, subtype=EventSubtypes.HTTP_API
        ):
            logger.debug("HTTP API event detected. Inferring a span")
            return create_inferred_span_from_http_api_event(
                event, context, decode_authorizer_context
            )
        elif event_source.equals(
            EventTypes.API_GATEWAY, subtype=EventSubtypes.WEBSOCKET
        ):
            logger.debug("API Gateway Websocket event detected. Inferring a span")
            return create_inferred_span_from_api_gateway_websocket_event(
                event, context, decode_authorizer_context
            )
        elif event_source.equals(EventTypes.SQS):
            logger.debug("SQS event detected. Inferring a span")
            return create_inferred_span_from_sqs_event(event, context)
        elif event_source.equals(EventTypes.SNS):
            logger.debug("SNS event detected. Inferring a span")
            return create_inferred_span_from_sns_event(event, context)
        elif event_source.equals(EventTypes.KINESIS):
            logger.debug("Kinesis event detected. Inferring a span")
            return create_inferred_span_from_kinesis_event(event, context)
        elif event_source.equals(EventTypes.DYNAMODB):
            logger.debug("Dynamodb event detected. Inferring a span")
            return create_inferred_span_from_dynamodb_event(event, context)
        elif event_source.equals(EventTypes.S3):
            logger.debug("S3 event detected. Inferring a span")
            return create_inferred_span_from_s3_event(event, context)
        elif event_source.equals(EventTypes.EVENTBRIDGE):
            logger.debug("Eventbridge event detected. Inferring a span")
            return create_inferred_span_from_eventbridge_event(event, context)
    except Exception as e:
        logger.debug(
            "Unable to infer span. Detected type: %s. Reason: %s",
            event_source.to_string(),
            e,
        )
    logger.debug("Unable to infer a span: unknown event type")


def create_service_mapping(val):
    new_service_mapping = {}
    for entry in val.split(","):
        parts = entry.split(":")
        if len(parts) == 2:
            key = parts[0].strip()
            value = parts[1].strip()
            if key != value and key and value:
                new_service_mapping[key] = value
    return new_service_mapping


def determine_service_name(
    service_mapping, specific_key, generic_key, extracted_key, fallback=None
):
    # Check for mapped service (specific key first, then generic key)
    mapped_service = service_mapping.get(specific_key) or service_mapping.get(
        generic_key
    )
    if mapped_service:
        return mapped_service

    # Check if AWS service representation is disabled
    aws_service_representation = os.environ.get(
        "DD_TRACE_AWS_SERVICE_REPRESENTATION_ENABLED", ""
    ).lower()
    if aws_service_representation in ("false", "0"):
        return fallback

    # Use extracted_key if it exists and is not empty, otherwise use fallback
    return (
        extracted_key.strip() if extracted_key and extracted_key.strip() else fallback
    )


# Initialization code
service_mapping_str = os.environ.get("DD_SERVICE_MAPPING", "")
service_mapping = create_service_mapping(service_mapping_str)

_dd_origin = {"_dd.origin": "lambda"}


def create_inferred_span_from_lambda_function_url_event(event, context):
    request_context = event.get("requestContext")
    api_id = request_context.get("apiId")
    domain = request_context.get("domainName")
    service_name = determine_service_name(service_mapping, api_id, "lambda_url", domain)
    http = request_context.get("http")
    method = http.get("method") if http else None
    path = http.get("path") if http else None
    http_url = f"https://{domain}{path}"
    resource = f"{method} {path}"
    tags = {
        "operation_name": "aws.lambda.url",
        "http.url": http_url,
        "endpoint": path,
        "http.method": method,
        "resource_names": resource,
        "request_id": context.aws_request_id,
    }
    request_time_epoch = request_context.get("timeEpoch")
    tracer.set_tags(_dd_origin)  # function urls don't count as lambda_inferred,
    # because they're in the same service as the inferring lambda function
    span = tracer.trace(
        "aws.lambda.url", service=service_name, resource=resource, span_type="http"
    )
    InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="sync")
    if span:
        span.set_tags(tags)
        span.start_ns = int(request_time_epoch * 1e6)
    return span


def is_api_gateway_invocation_async(event):
    hdrs = event.get("headers")
    if not hdrs:
        return False
    return hdrs.get("X-Amz-Invocation-Type") == "Event"


def insert_upstream_authorizer_span(
    kwargs_to_start_span, other_tags_for_span, start_time_ns, finish_time_ns
):
    """Insert the authorizer span.
        Without this:        parent span --child-> inferred span
        With this insertion: parent span --child-> upstreamAuthorizerSpan --child-> inferred span

    Args:
        kwargs_to_start_span (Dict): the same keyword arguments used for the inferred span
        other_tags_for_span (Dict): the same tag keyword arguments used for the inferred span
        start_time_ns (int): the start time of the span in nanoseconds
        finish_time_ns (int): the finish time of the sapn in nanoseconds
    """
    trace_ctx = tracer.current_trace_context()
    upstream_authorizer_span = tracer.trace(
        "aws.apigateway.authorizer", **kwargs_to_start_span
    )
    upstream_authorizer_span.set_tags(other_tags_for_span)
    upstream_authorizer_span.set_tag("operation_name", "aws.apigateway.authorizer")
    # always sync for the authorizer invocation
    InferredSpanInfo.set_tags_to_span(upstream_authorizer_span, synchronicity="sync")
    upstream_authorizer_span.start_ns = int(start_time_ns)
    upstream_authorizer_span.finish(finish_time_ns / 1e9)
    # trace context needs to be set again as it is reset by finish()
    tracer.context_provider.activate(trace_ctx)
    return upstream_authorizer_span


def process_injected_data(event, request_time_epoch_ms, args, tags):
    """
    This covers the ApiGateway RestAPI and Websocket cases. It doesn't cover Http API cases.
    """
    injected_authorizer_data = get_injected_authorizer_data(event, False)
    if injected_authorizer_data:
        try:
            start_time_ns = int(
                injected_authorizer_data.get(Headers.Parent_Span_Finish_Time)
            )
            finish_time_ns = (
                request_time_epoch_ms
                + (
                    int(
                        event["requestContext"]["authorizer"].get(
                            "integrationLatency", 0
                        )
                    )
                )
            ) * 1e6
            upstream_authorizer_span = insert_upstream_authorizer_span(
                args, tags, start_time_ns, finish_time_ns
            )
            return upstream_authorizer_span, finish_time_ns
        except Exception as e:
            logger.debug(
                "Unable to insert authorizer span. Continue to generate the main span.\
                 Reason: %s",
                e,
            )
            return None, None
    else:
        return None, None


def create_inferred_span_from_api_gateway_websocket_event(
    event, context, decode_authorizer_context: bool = True
):
    request_context = event.get("requestContext")
    domain = request_context.get("domainName")
    endpoint = request_context.get("routeKey")
    http_url = f"https://{domain}{endpoint}"
    api_id = request_context.get("apiId")

    service_name = determine_service_name(
        service_mapping, api_id, "lambda_api_gateway", domain
    )
    tags = {
        "operation_name": "aws.apigateway.websocket",
        "http.url": http_url,
        "endpoint": endpoint,
        "resource_names": endpoint,
        "span.kind": "server",
        "apiid": api_id,
        "apiname": api_id,
        "stage": request_context.get("stage"),
        "request_id": context.aws_request_id,
        "connection_id": request_context.get("connectionId"),
        "event_type": request_context.get("eventType"),
        "message_direction": request_context.get("messageDirection"),
    }
    request_time_epoch_ms = int(request_context.get("requestTimeEpoch"))
    if is_api_gateway_invocation_async(event):
        InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="async")
    else:
        InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="sync")
    args = {
        "service": service_name,
        "resource": endpoint,
        "span_type": "web",
    }
    tracer.set_tags(_dd_origin)
    upstream_authorizer_span = None
    finish_time_ns = None
    if decode_authorizer_context:
        upstream_authorizer_span, finish_time_ns = process_injected_data(
            event, request_time_epoch_ms, args, tags
        )
    span = tracer.trace("aws.apigateway.websocket", **args)
    if span:
        span.set_tags(tags)
        span.start_ns = int(
            finish_time_ns
            if finish_time_ns is not None
            else request_time_epoch_ms * 1e6
        )
        if upstream_authorizer_span:
            span.parent_id = upstream_authorizer_span.span_id
    return span


def create_inferred_span_from_api_gateway_event(
    event, context, decode_authorizer_context: bool = True
):
    request_context = event.get("requestContext")
    domain = request_context.get("domainName", "")
    api_id = request_context.get("apiId")
    service_name = determine_service_name(
        service_mapping, api_id, "lambda_api_gateway", domain
    )
    method = event.get("httpMethod")
    path = event.get("path")
    http_url = f"https://{domain}{path}"
    resource_path = _get_resource_path(event, request_context)
    resource = f"{method} {resource_path}"
    tags = {
        "operation_name": "aws.apigateway.rest",
        "http.url": http_url,
        "endpoint": path,
        "http.method": method,
        "resource_names": resource,
        "span.kind": "server",
        "apiid": api_id,
        "apiname": api_id,
        "stage": request_context.get("stage"),
        "request_id": context.aws_request_id,
    }
    request_time_epoch_ms = int(request_context.get("requestTimeEpoch"))
    if is_api_gateway_invocation_async(event):
        InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="async")
    else:
        InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="sync")
    args = {
        "service": service_name,
        "resource": resource,
        "span_type": "http",
    }
    tracer.set_tags(_dd_origin)
    upstream_authorizer_span = None
    finish_time_ns = None
    if decode_authorizer_context:
        upstream_authorizer_span, finish_time_ns = process_injected_data(
            event, request_time_epoch_ms, args, tags
        )
    span = tracer.trace("aws.apigateway", **args)
    if span:
        span.set_tags(tags)
        # start time pushed by the inserted authorizer span
        span.start_ns = int(
            finish_time_ns
            if finish_time_ns is not None
            else request_time_epoch_ms * 1e6
        )
        if upstream_authorizer_span:
            span.parent_id = upstream_authorizer_span.span_id
    return span


def _get_resource_path(event, request_context):
    route_key = request_context.get("routeKey") or ""
    if "{" in route_key:
        try:
            return route_key.split(" ")[1]
        except Exception as e:
            logger.debug("Error parsing routeKey: %s", e)
    return event.get("rawPath") or request_context.get("resourcePath") or route_key


def create_inferred_span_from_http_api_event(
    event, context, decode_authorizer_context: bool = True
):
    request_context = event.get("requestContext")
    domain = request_context.get("domainName")
    api_id = request_context.get("apiId")
    service_name = determine_service_name(
        service_mapping, api_id, "lambda_api_gateway", domain
    )
    http = request_context.get("http") or {}
    method = http.get("method")
    path = event.get("rawPath")
    http_url = f"https://{domain}{path}"
    resource_path = _get_resource_path(event, request_context)
    resource = f"{method} {resource_path}"
    tags = {
        "operation_name": "aws.httpapi",
        "endpoint": path,
        "http.url": http_url,
        "http.method": http.get("method"),
        "http.protocol": http.get("protocol"),
        "http.source_ip": http.get("sourceIp"),
        "http.user_agent": http.get("userAgent"),
        "resource_names": resource,
        "request_id": context.aws_request_id,
        "apiid": api_id,
        "apiname": api_id,
        "stage": request_context.get("stage"),
    }
    request_time_epoch_ms = int(request_context.get("timeEpoch"))
    if is_api_gateway_invocation_async(event):
        InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="async")
    else:
        InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="sync")
    tracer.set_tags(_dd_origin)
    inferred_span_start_ns = request_time_epoch_ms * 1e6
    if decode_authorizer_context:
        injected_authorizer_data = get_injected_authorizer_data(event, True)
        if injected_authorizer_data:
            inferred_span_start_ns = injected_authorizer_data.get(
                Headers.Parent_Span_Finish_Time
            )
    span = tracer.trace(
        "aws.httpapi", service=service_name, resource=resource, span_type="http"
    )
    if span:
        span.set_tags(tags)
        span.start_ns = int(inferred_span_start_ns)
    return span


def create_inferred_span_from_sqs_event(event, context):
    trace_ctx = tracer.current_trace_context()

    event_record = get_first_record(event)
    event_source_arn = event_record.get("eventSourceARN")
    queue_name = event_source_arn.split(":")[-1]
    service_name = determine_service_name(
        service_mapping, queue_name, "lambda_sqs", queue_name, "sqs"
    )
    attrs = event_record.get("attributes") or {}
    tags = {
        "operation_name": "aws.sqs",
        "resource_names": queue_name,
        "span.kind": "server",
        "queuename": queue_name,
        "event_source_arn": event_source_arn,
        "receipt_handle": event_record.get("receiptHandle"),
        "sender_id": attrs.get("SenderId"),
    }
    InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="async")
    request_time_epoch = attrs.get("SentTimestamp")
    start_time = int(request_time_epoch) / 1000

    upstream_span = None
    if "body" in event_record:
        body_str = event_record.get("body", {})
        try:
            body = json.loads(body_str)

            # logic to deal with SNS => SQS event
            if body.get("Type", "") == "Notification" and "TopicArn" in body:
                logger.debug("Found SNS message inside SQS event")
                upstream_span = create_inferred_span_from_sns_event(
                    create_sns_event(body), context
                )
                upstream_span.finish(finish_time=start_time)

            # EventBridge => SQS
            elif body.get("detail"):
                detail = body.get("detail")
                if detail.get("_datadog"):
                    logger.debug("Found an EventBridge message inside SQS event")
                    upstream_span = create_inferred_span_from_eventbridge_event(
                        body, context
                    )
                    upstream_span.finish(finish_time=start_time)

        except Exception as e:
            logger.debug(
                "Unable to create upstream span from SQS message, with error %s", e
            )
            pass

    # trace context needs to be set again as it is reset
    # when sns_span.finish executes
    tracer.context_provider.activate(trace_ctx)
    tracer.set_tags(_dd_origin)
    span = tracer.trace(
        "aws.sqs", service=service_name, resource=queue_name, span_type="web"
    )
    if span:
        span.set_tags(tags)
    span.start = start_time
    if upstream_span:
        span.parent_id = upstream_span.span_id

    return span


def create_inferred_span_from_sns_event(event, context):
    event_record = get_first_record(event)
    sns_message = event_record.get("Sns") or {}
    topic_arn = sns_message.get("TopicArn")
    topic_name = topic_arn.split(":")[-1]
    service_name = determine_service_name(
        service_mapping, topic_name, "lambda_sns", topic_name, "sns"
    )
    tags = {
        "operation_name": "aws.sns",
        "resource_names": topic_name,
        "span.kind": "server",
        "topicname": topic_name,
        "topic_arn": topic_arn,
        "message_id": sns_message.get("MessageId"),
        "type": sns_message.get("Type"),
    }

    # Subject not available in SNS => SQS scenario
    subject = sns_message.get("Subject")
    if subject:
        tags["subject"] = subject

    InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="async")
    sns_dt_format = "%Y-%m-%dT%H:%M:%S.%fZ"
    timestamp = sns_message.get("Timestamp")
    dt = datetime.strptime(timestamp, sns_dt_format)

    tracer.set_tags(_dd_origin)
    span = tracer.trace(
        "aws.sns", service=service_name, resource=topic_name, span_type="web"
    )
    if span:
        span.set_tags(tags)
    span.start = dt.replace(tzinfo=timezone.utc).timestamp()
    return span


def create_inferred_span_from_kinesis_event(event, context):
    event_record = get_first_record(event)
    event_source_arn = event_record.get("eventSourceARN")
    event_id = event_record.get("eventID")
    stream_name = re.sub(r"^stream/", "", (event_source_arn or "").split(":")[-1])
    shard_id = event_id.split(":")[0]
    service_name = determine_service_name(
        service_mapping, stream_name, "lambda_kinesis", stream_name, "kinesis"
    )
    kinesis = event_record.get("kinesis") or {}
    tags = {
        "operation_name": "aws.kinesis",
        "resource_names": stream_name,
        "span.kind": "server",
        "streamname": stream_name,
        "shardid": shard_id,
        "event_source_arn": event_source_arn,
        "event_id": event_id,
        "event_name": event_record.get("eventName"),
        "event_version": event_record.get("eventVersion"),
        "partition_key": kinesis.get("partitionKey"),
    }
    InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="async")
    request_time_epoch = kinesis.get("approximateArrivalTimestamp")

    tracer.set_tags(_dd_origin)
    span = tracer.trace(
        "aws.kinesis", service=service_name, resource=stream_name, span_type="web"
    )
    if span:
        span.set_tags(tags)
    span.start = request_time_epoch
    return span


def create_inferred_span_from_dynamodb_event(event, context):
    event_record = get_first_record(event)
    event_source_arn = event_record.get("eventSourceARN")
    table_name = event_source_arn.split("/")[1]
    service_name = determine_service_name(
        service_mapping, table_name, "lambda_dynamodb", table_name, "dynamodb"
    )
    dynamodb_message = event_record.get("dynamodb") or {}
    tags = {
        "operation_name": "aws.dynamodb",
        "resource_names": table_name,
        "span.kind": "server",
        "tablename": table_name,
        "event_source_arn": event_source_arn,
        "event_id": event_record.get("eventID"),
        "event_name": event_record.get("eventName"),
        "event_version": event_record.get("eventVersion"),
        "stream_view_type": dynamodb_message.get("StreamViewType"),
        "size_bytes": str(dynamodb_message.get("SizeBytes")),
    }
    InferredSpanInfo.set_tags(tags, synchronicity="async", tag_source="self")
    request_time_epoch = dynamodb_message.get("ApproximateCreationDateTime")
    tracer.set_tags(_dd_origin)
    span = tracer.trace(
        "aws.dynamodb", service=service_name, resource=table_name, span_type="web"
    )
    if span:
        span.set_tags(tags)

    span.start = int(request_time_epoch)
    return span


def create_inferred_span_from_s3_event(event, context):
    event_record = get_first_record(event)
    s3 = event_record.get("s3") or {}
    bucket = s3.get("bucket") or {}
    obj = s3.get("object") or {}
    bucket_name = bucket.get("name")
    service_name = determine_service_name(
        service_mapping, bucket_name, "lambda_s3", bucket_name, "s3"
    )
    tags = {
        "operation_name": "aws.s3",
        "resource_names": bucket_name,
        "span.kind": "server",
        "event_name": event_record.get("eventName"),
        "bucketname": bucket_name,
        "bucket_arn": bucket.get("arn"),
        "object_key": obj.get("key"),
        "object_size": str(obj.get("size")),
        "object_etag": obj.get("eTag"),
    }
    InferredSpanInfo.set_tags(tags, synchronicity="async", tag_source="self")
    dt_format = "%Y-%m-%dT%H:%M:%S.%fZ"
    timestamp = event_record.get("eventTime")
    dt = datetime.strptime(timestamp, dt_format)

    tracer.set_tags(_dd_origin)
    span = tracer.trace(
        "aws.s3", service=service_name, resource=bucket_name, span_type="web"
    )
    if span:
        span.set_tags(tags)
    span.start = dt.replace(tzinfo=timezone.utc).timestamp()
    return span


def create_inferred_span_from_eventbridge_event(event, context):
    source = event.get("source")
    service_name = determine_service_name(
        service_mapping, source, "lambda_eventbridge", source, "eventbridge"
    )
    tags = {
        "operation_name": "aws.eventbridge",
        "resource_names": source,
        "span.kind": "server",
        "detail_type": event.get("detail-type"),
    }
    InferredSpanInfo.set_tags(
        tags,
        synchronicity="async",
        tag_source="self",
    )

    timestamp = event.get("time")
    dt_format = "%Y-%m-%dT%H:%M:%SZ"

    # Use more granular timestamp from upstream Step Function if possible
    try:
        if is_step_function_event(event.get("detail")):
            timestamp = event["detail"]["_datadog"]["State"]["EnteredTime"]
            dt_format = "%Y-%m-%dT%H:%M:%S.%fZ"
    except (TypeError, KeyError, AttributeError):
        logger.debug("Error parsing timestamp from Step Functions event")

    dt = datetime.strptime(timestamp, dt_format)

    tracer.set_tags(_dd_origin)
    span = tracer.trace(
        "aws.eventbridge", service=service_name, resource=source, span_type="web"
    )
    if span:
        span.set_tags(tags)
    span.start = dt.replace(tzinfo=timezone.utc).timestamp()

    # Since inferred span will later parent Lambda, preserve Lambda's current parent
    if dd_trace_context.span_id:
        span.parent_id = dd_trace_context.span_id

    return span


def create_function_execution_span(
    context,
    function_name,
    is_cold_start,
    is_proactive_init,
    trace_context_source,
    merge_xray_traces,
    trigger_tags,
    parent_span=None,
    span_pointers=None,
):
    tags = None
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
            "functionname": (
                context.function_name.lower() if context.function_name else None
            ),
            "datadog_lambda": datadog_lambda_version,
            "dd_trace": ddtrace_version,
            "span.name": "aws.lambda",
        }
    tags = tags or {}
    if is_proactive_init:
        tags["proactive_initialization"] = str(is_proactive_init).lower()
    if trace_context_source == TraceContextSource.XRAY and merge_xray_traces:
        tags["_dd.parent_source"] = trace_context_source
    tags.update(trigger_tags)
    tracer.set_tags(_dd_origin)
    # Determine service name based on config and env var
    if config.service:
        service_name = config.service
    else:
        aws_service_representation = os.environ.get(
            "DD_TRACE_AWS_SERVICE_REPRESENTATION_ENABLED", ""
        ).lower()
        if aws_service_representation in ("false", "0"):
            service_name = "aws.lambda"
        else:
            service_name = function_name if function_name else "aws.lambda"

    span = tracer.trace(
        "aws.lambda",
        service=service_name,
        resource=function_name,
        span_type="serverless",
    )
    if span:
        span.set_tags(tags)
    if parent_span:
        span.parent_id = parent_span.span_id
    if span_pointers:
        root_span = parent_span if parent_span else span
        for span_pointer_description in span_pointers:
            root_span._add_span_pointer(
                pointer_kind=span_pointer_description.pointer_kind,
                pointer_direction=span_pointer_description.pointer_direction,
                pointer_hash=span_pointer_description.pointer_hash,
                extra_attributes=span_pointer_description.extra_attributes,
            )
    return span


def mark_trace_as_error_for_5xx_responses(context, status_code, span):
    if len(status_code) == 3 and status_code.startswith("5"):
        submit_errors_metric(context)
        if span:
            span.error = 1


class InferredSpanInfo(object):
    BASE_NAME = "_inferred_span"
    SYNCHRONICITY = f"{BASE_NAME}.synchronicity"
    TAG_SOURCE = f"{BASE_NAME}.tag_source"

    @staticmethod
    def set_tags(
        tags: Dict[str, str],
        synchronicity: Optional[Literal["sync", "async"]] = None,
        tag_source: Optional[Literal["labmda", "self"]] = None,
    ):
        if synchronicity is not None:
            tags[InferredSpanInfo.SYNCHRONICITY] = str(synchronicity)
        if tag_source is not None:
            tags[InferredSpanInfo.TAG_SOURCE] = str(tag_source)

    @staticmethod
    def set_tags_to_span(
        span: Span,
        synchronicity: Optional[Literal["sync", "async"]] = None,
        tag_source: Optional[Literal["labmda", "self"]] = None,
    ):
        if synchronicity is not None:
            span.set_tags({InferredSpanInfo.SYNCHRONICITY: synchronicity})
        if tag_source is not None:
            span.set_tags({InferredSpanInfo.TAG_SOURCE: str(tag_source)})

    @staticmethod
    def is_async(span: Span) -> bool:
        if not span:
            return False
        try:
            return span.get_tag(InferredSpanInfo.SYNCHRONICITY) == "async"
        except Exception as e:
            logger.debug(
                "Unabled to read the %s tag, returning False. \
                Reason: %s.",
                InferredSpanInfo.SYNCHRONICITY,
                e,
            )
            return False


def emit_telemetry_on_exception_outside_of_handler(
    exception, resource_name, handler_load_start_time_ns
):
    """
    Emit an enhanced error metric and create a span for exceptions occurring outside the handler
    """
    submit_errors_metric(None)
    if config.trace_enabled:
        span = tracer.trace(
            "aws.lambda",
            service="aws.lambda",
            resource=resource_name,
            span_type="serverless",
        )
        span.start_ns = handler_load_start_time_ns

        tags = {
            "error.status": 500,
            "error.type": type(exception).__name__,
            "error.message": exception,
            "error.stack": traceback.format_exc(),
            "resource_names": resource_name,
            "resource.name": resource_name,
            "operation_name": "aws.lambda",
            "status": "error",
        }
        span.set_tags(tags)
        span.error = 1
        span.finish()
