# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.
import hashlib
import logging
import os
import json
import base64
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
    TraceHeader,
    TraceContextSource,
    XrayDaemon,
    Headers,
)
from datadog_lambda.xray import (
    send_segment,
    parse_xray_header,
)
from ddtrace import tracer, patch, Span
from ddtrace import __version__ as ddtrace_version
from ddtrace.propagation.http import HTTPPropagator
from datadog_lambda import __version__ as datadog_lambda_version
from datadog_lambda.trigger import (
    _EventSource,
    parse_event_source,
    get_first_record,
    EventTypes,
    EventSubtypes,
)

logger = logging.getLogger(__name__)

dd_trace_context = {}
dd_tracing_enabled = os.environ.get("DD_TRACE_ENABLED", "false").lower() == "true"

propagator = HTTPPropagator()


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

    xray_trace_entity = parse_xray_header(
        os.environ.get(XrayDaemon.XRAY_TRACE_ID_HEADER_NAME, "")
    )
    if xray_trace_entity is None:
        return None
    trace_context = {
        "trace-id": _convert_xray_trace_id(xray_trace_entity.get("trace_id")),
        "parent-id": _convert_xray_entity_id(xray_trace_entity.get("parent_id")),
        "sampling-priority": _convert_xray_sampling(xray_trace_entity.get("sampled")),
    }
    logger.debug(
        "Converted trace context %s from X-Ray segment %s",
        trace_context,
        (
            xray_trace_entity["trace_id"],
            xray_trace_entity["parent_id"],
            xray_trace_entity["sampled"],
        ),
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
    send_segment(subsegment_metadata_key, subsegment_metadata_value)


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
        if injected_authorizer_data:
            try:
                # fail fast on any KeyError here
                trace_id = injected_authorizer_data[TraceHeader.TRACE_ID]
                parent_id = injected_authorizer_data[TraceHeader.PARENT_ID]
                sampling_priority = injected_authorizer_data.get(
                    TraceHeader.SAMPLING_PRIORITY
                )
                return trace_id, parent_id, sampling_priority
            except Exception as e:
                logger.debug(
                    "extract_context_from_authorizer_event returned with error. \
                     Continue without injecting the authorizer span %s",
                    e,
                )

    headers = event.get("headers", {}) or {}
    lowercase_headers = {k.lower(): v for k, v in headers.items()}

    trace_id = lowercase_headers.get(TraceHeader.TRACE_ID)
    parent_id = lowercase_headers.get(TraceHeader.PARENT_ID)
    sampling_priority = lowercase_headers.get(TraceHeader.SAMPLING_PRIORITY)

    if not trace_id or not parent_id or not sampling_priority:
        return extract_context_from_lambda_context(lambda_context)

    return trace_id, parent_id, sampling_priority


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


def extract_context_from_sqs_or_sns_event_or_context(event, lambda_context):
    """
    Extract Datadog trace context from an SQS event.

    The extraction chain goes as follows:
    EB => SQS (First records body contains EB context), or
    SNS => SQS (First records body contains SNS context), or
    SQS or SNS (`messageAttributes` for SQS context,
                `MessageAttributes` for SNS context), else
    Lambda Context.

    Falls back to lambda context if no trace data is found in the SQS message attributes.
    """

    # EventBridge => SQS
    try:
        (
            trace_id,
            parent_id,
            sampling_priority,
        ) = _extract_context_from_eventbridge_sqs_event(event)
        return trace_id, parent_id, sampling_priority
    except Exception:
        logger.debug("Failed extracting context as EventBridge to SQS.")

    try:
        first_record = event.get("Records")[0]

        # logic to deal with SNS => SQS event
        if "body" in first_record:
            body_str = first_record.get("body", {})
            try:
                body = json.loads(body_str)
                if body.get("Type", "") == "Notification" and "TopicArn" in body:
                    logger.debug("Found SNS message inside SQS event")
                    first_record = get_first_record(create_sns_event(body))
            except Exception:
                first_record = event.get("Records")[0]
                pass

        msg_attributes = first_record.get(
            "messageAttributes",
            first_record.get("Sns", {}).get("MessageAttributes", {}),
        )
        dd_payload = msg_attributes.get("_datadog", {})
        # SQS uses dataType and binaryValue/stringValue
        # SNS uses Type and Value
        dd_json_data_type = dd_payload.get("Type", dd_payload.get("dataType", ""))
        if dd_json_data_type == "Binary":
            dd_json_data = dd_payload.get(
                "binaryValue",
                dd_payload.get("Value", r"{}"),
            )
            dd_json_data = base64.b64decode(dd_json_data)
        elif dd_json_data_type == "String":
            dd_json_data = dd_payload.get(
                "stringValue",
                dd_payload.get("Value", r"{}"),
            )
        else:
            logger.debug(
                "Datadog Lambda Python only supports extracting trace"
                "context from String or Binary SQS/SNS message attributes"
            )
        dd_data = json.loads(dd_json_data)
        trace_id = dd_data.get(TraceHeader.TRACE_ID)
        parent_id = dd_data.get(TraceHeader.PARENT_ID)
        sampling_priority = dd_data.get(TraceHeader.SAMPLING_PRIORITY)

        return trace_id, parent_id, sampling_priority
    except Exception as e:
        logger.debug("The trace extractor returned with error %s", e)
        return extract_context_from_lambda_context(lambda_context)


def _extract_context_from_eventbridge_sqs_event(event):
    """
    Extracts Datadog trace context from an SQS event triggered by
    EventBridge.

    This is only possible if first record in `Records` contains a
    `body` field which contains the EventBridge `detail` as a JSON string.
    """
    try:
        first_record = event.get("Records")[0]
        if "body" in first_record:
            body_str = first_record.get("body", {})
            body = json.loads(body_str)

            detail = body.get("detail")
            dd_context = detail.get("_datadog")
            trace_id = dd_context.get(TraceHeader.TRACE_ID)
            parent_id = dd_context.get(TraceHeader.PARENT_ID)
            sampling_priority = dd_context.get(TraceHeader.SAMPLING_PRIORITY)
            return trace_id, parent_id, sampling_priority
    except Exception:
        raise


def extract_context_from_eventbridge_event(event, lambda_context):
    """
    Extract datadog trace context from an EventBridge message's Details.
    This is only possible if Details is a JSON string.
    """
    try:
        detail = event.get("detail")
        dd_context = detail.get("_datadog")
        if not dd_context:
            return extract_context_from_lambda_context(lambda_context)
        trace_id = dd_context.get(TraceHeader.TRACE_ID)
        parent_id = dd_context.get(TraceHeader.PARENT_ID)
        sampling_priority = dd_context.get(TraceHeader.SAMPLING_PRIORITY)
        return trace_id, parent_id, sampling_priority
    except Exception as e:
        logger.debug("The trace extractor returned with error %s", e)
        return extract_context_from_lambda_context(lambda_context)


def extract_context_from_kinesis_event(event, lambda_context):
    """
    Extract datadog trace context from a Kinesis Stream's base64 encoded data string
    """
    try:
        record = get_first_record(event)
        data = record.get("kinesis", {}).get("data", None)
        if data:
            b64_bytes = data.encode("ascii")
            str_bytes = base64.b64decode(b64_bytes)
            data_str = str_bytes.decode("ascii")
            data_obj = json.loads(data_str)
            dd_ctx = data_obj.get("_datadog")

        if not dd_ctx:
            return extract_context_from_lambda_context(lambda_context)

        trace_id = dd_ctx.get(TraceHeader.TRACE_ID)
        parent_id = dd_ctx.get(TraceHeader.PARENT_ID)
        sampling_priority = dd_ctx.get(TraceHeader.SAMPLING_PRIORITY)
        return trace_id, parent_id, sampling_priority
    except Exception as e:
        logger.debug("The trace extractor returned with error %s", e)
        return extract_context_from_lambda_context(lambda_context)


def _deterministic_md5_hash(s: str) -> str:
    """MD5 here is to generate trace_id, not for any encryption."""
    hex_number = hashlib.md5(s.encode("ascii")).hexdigest()
    binary = bin(int(hex_number, 16))
    binary_str = str(binary)
    binary_str_remove_0b = binary_str[2:].rjust(128, "0")
    most_significant_64_bits_without_leading_1 = "0" + binary_str_remove_0b[1:-64]
    result = str(int(most_significant_64_bits_without_leading_1, 2))
    if result == "0" * 64:
        return "1"
    return result


def extract_context_from_step_functions(event, lambda_context):
    """
    Only extract datadog trace context when Step Functions Context Object is injected
    into lambda's event dict.
    """
    try:
        execution_id = event.get("Execution").get("Id")
        state_name = event.get("State").get("Name")
        state_entered_time = event.get("State").get("EnteredTime")
        trace_id = _deterministic_md5_hash(execution_id)
        parent_id = _deterministic_md5_hash(
            execution_id + "#" + state_name + "#" + state_entered_time
        )
        sampling_priority = SamplingPriority.AUTO_KEEP
        return trace_id, parent_id, sampling_priority
    except Exception as e:
        logger.debug("The Step Functions trace extractor returned with error %s", e)
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
        authorizer_headers = event.get("requestContext", {}).get("authorizer")
        if not authorizer_headers:
            return None

        dd_data_raw = (
            authorizer_headers.get("lambda", {}).get("_datadog")
            if is_http_api
            else authorizer_headers.get("_datadog")
        )

        if not dd_data_raw:
            return None

        injected_data = json.loads(base64.b64decode(dd_data_raw))

        # Lambda authorizer's results can be cached. But the payload will still have the injected
        # data in cached requests. How to distinguish cached case and ignore the injected data ?
        # APIGateway automatically injects a integrationLatency data in some cases. If it's >0 we
        # know that it's not cached. But integrationLatency is not available for Http API case. In
        # that case, we use the injected Authorizing_Request_Id to tell if it's cached. But token
        # authorizers don't pass on the requestId. The Authorizing_Request_Id can't work for all
        # cases neither. As a result, we combine both methods as shown below.
        if authorizer_headers.get("integrationLatency", 0) > 0 or event.get(
            "requestContext", {}
        ).get("requestId") == injected_data.get(Headers.Authorizing_Request_Id):
            return injected_data
        else:
            return None

    except Exception as e:
        logger.debug("Failed to check if invocated by an authorizer. error %s", e)
        return None


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
        (
            trace_id,
            parent_id,
            sampling_priority,
        ) = extract_context_custom_extractor(extractor, event, lambda_context)
    elif isinstance(event, (set, dict)) and "headers" in event:
        (
            trace_id,
            parent_id,
            sampling_priority,
        ) = extract_context_from_http_event_or_context(
            event, lambda_context, event_source, decode_authorizer_context
        )
    elif event_source.equals(EventTypes.SNS) or event_source.equals(EventTypes.SQS):
        (
            trace_id,
            parent_id,
            sampling_priority,
        ) = extract_context_from_sqs_or_sns_event_or_context(event, lambda_context)
    elif event_source.equals(EventTypes.EVENTBRIDGE):
        (
            trace_id,
            parent_id,
            sampling_priority,
        ) = extract_context_from_eventbridge_event(event, lambda_context)
    elif event_source.equals(EventTypes.KINESIS):
        (
            trace_id,
            parent_id,
            sampling_priority,
        ) = extract_context_from_kinesis_event(event, lambda_context)
    elif event_source.equals(EventTypes.STEPFUNCTIONS):
        (
            trace_id,
            parent_id,
            sampling_priority,
        ) = extract_context_from_step_functions(event, lambda_context)
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
    return dd_trace_context, trace_context_source, event_source


def get_dd_trace_context():
    """
    Return the Datadog trace context to be propagated on the outgoing requests.

    If the Lambda function is invoked by a Datadog-traced service, a Datadog
    trace context may already exist, and it should be used. Otherwise, use the
    current X-Ray trace entity, or the dd-trace-py context if DD_TRACE_ENABLED is true.

    Most of widely-used HTTP clients are patched to inject the context
    automatically, but this function can be used to manually inject the trace
    context to an outgoing request.
    """
    if dd_tracing_enabled:
        dd_trace_py_context = _get_dd_trace_py_context()
        if dd_trace_py_context is not None:
            return _context_obj_to_headers(dd_trace_py_context)

    global dd_trace_context

    try:
        xray_context = _get_xray_trace_context()  # xray (sub)segment
    except Exception as e:
        logger.debug(
            "get_dd_trace_context couldn't read from segment from x-ray, with error %s"
            % e
        )
    if not xray_context:
        return {}

    if not dd_trace_context:
        return _context_obj_to_headers(xray_context)

    context = dd_trace_context.copy()
    context["parent-id"] = xray_context.get("parent-id")
    logger.debug("Set parent id from xray trace context: %s", context.get("parent-id"))

    return _context_obj_to_headers(context)


def set_correlation_ids():
    """
    Create a dummy span, and overrides its trace_id and span_id, to make
    ddtrace.helpers.get_log_correlation_context() return a dict containing the correct ids for both
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
    if not context:
        return

    span = tracer.trace("dummy.span")
    span.trace_id = int(context[TraceHeader.TRACE_ID])
    span.span_id = int(context[TraceHeader.PARENT_ID])

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
    return os.environ.get(XrayDaemon.FUNCTION_NAME_HEADER_NAME, "") != ""


def set_dd_trace_py_root(trace_context_source, merge_xray_traces):
    if trace_context_source == TraceContextSource.EVENT or merge_xray_traces:
        context = dict(dd_trace_context)
        if merge_xray_traces:
            xray_context = _get_xray_trace_context()
            if xray_context is not None:
                context["parent-id"] = xray_context.get("parent-id")

        headers = _context_obj_to_headers(context)
        span_context = propagator.extract(headers)
        tracer.context_provider.activate(span_context)
        logger.debug(
            "Set dd trace root context to: %s",
            (span_context.trace_id, span_context.span_id),
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
        return None
    logger.debug("Unable to infer a span: unknown event type")
    return None


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


def determine_service_name(service_mapping, specific_key, generic_key, default_value):
    service_name = service_mapping.get(specific_key)
    if service_name is None:
        service_name = service_mapping.get(generic_key, default_value)
    return service_name


service_mapping = {}
# Initialization code
service_mapping_str = os.getenv("DD_SERVICE_MAPPING", "")
service_mapping = create_service_mapping(service_mapping_str)


def create_inferred_span_from_lambda_function_url_event(event, context):
    request_context = event.get("requestContext")
    api_id = request_context.get("apiId")
    domain = request_context.get("domainName")
    service_name = determine_service_name(service_mapping, api_id, "lambda_url", domain)
    method = request_context.get("http", {}).get("method")
    path = request_context.get("http", {}).get("path")
    resource = "{0} {1}".format(method, path)
    tags = {
        "operation_name": "aws.lambda.url",
        "http.url": domain + path,
        "endpoint": path,
        "http.method": method,
        "resource_names": domain + path,
        "request_id": context.aws_request_id,
    }
    request_time_epoch = request_context.get("timeEpoch")
    args = {
        "service": service_name,
        "resource": resource,
        "span_type": "http",
    }
    tracer.set_tags(
        {"_dd.origin": "lambda"}
    )  # function urls don't count as lambda_inferred,
    # because they're in the same service as the inferring lambda function
    span = tracer.trace("aws.lambda.url", **args)
    InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="sync")
    if span:
        span.set_tags(tags)
    span.start = request_time_epoch / 1000
    return span


def is_api_gateway_invocation_async(event):
    return event.get("headers", {}).get("X-Amz-Invocation-Type") == "Event"


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
    api_id = request_context.get("apiId")

    service_name = determine_service_name(
        service_mapping, api_id, "lambda_api_gateway", domain
    )
    tags = {
        "operation_name": "aws.apigateway.websocket",
        "http.url": domain + endpoint,
        "endpoint": endpoint,
        "resource_names": endpoint,
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
    tracer.set_tags({"_dd.origin": "lambda"})
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
    resource = "{0} {1}".format(method, path)
    tags = {
        "operation_name": "aws.apigateway.rest",
        "http.url": domain + path,
        "endpoint": path,
        "http.method": method,
        "resource_names": resource,
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
    tracer.set_tags({"_dd.origin": "lambda"})
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


def create_inferred_span_from_http_api_event(
    event, context, decode_authorizer_context: bool = True
):
    request_context = event.get("requestContext")
    domain = request_context.get("domainName")
    api_id = request_context.get("apiId")
    service_name = determine_service_name(
        service_mapping, api_id, "lambda_api_gateway", domain
    )
    method = request_context.get("http", {}).get("method")
    path = event.get("rawPath")
    resource = "{0} {1}".format(method, path)
    tags = {
        "operation_name": "aws.httpapi",
        "endpoint": path,
        "http.url": domain + path,
        "http.method": request_context.get("http", {}).get("method"),
        "http.protocol": request_context.get("http", {}).get("protocol"),
        "http.source_ip": request_context.get("http", {}).get("sourceIp"),
        "http.user_agent": request_context.get("http", {}).get("userAgent"),
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
    args = {
        "service": service_name,
        "resource": resource,
        "span_type": "http",
    }
    tracer.set_tags({"_dd.origin": "lambda"})
    inferred_span_start_ns = request_time_epoch_ms * 1e6
    if decode_authorizer_context:
        injected_authorizer_data = get_injected_authorizer_data(event, True)
        if injected_authorizer_data:
            inferred_span_start_ns = injected_authorizer_data.get(
                Headers.Parent_Span_Finish_Time
            )
    span = tracer.trace("aws.httpapi", **args)
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
        service_mapping, queue_name, "lambda_sqs", "sqs"
    )
    tags = {
        "operation_name": "aws.sqs",
        "resource_names": queue_name,
        "queuename": queue_name,
        "event_source_arn": event_source_arn,
        "receipt_handle": event_record.get("receiptHandle"),
        "sender_id": event_record.get("attributes", {}).get("SenderId"),
    }
    InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="async")
    request_time_epoch = event_record.get("attributes", {}).get("SentTimestamp")
    args = {
        "service": service_name,
        "resource": queue_name,
        "span_type": "web",
    }
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
                "Unable to create upstream span from SQS message, with error %s" % e
            )
            pass

    # trace context needs to be set again as it is reset
    # when sns_span.finish executes
    tracer.context_provider.activate(trace_ctx)
    tracer.set_tags({"_dd.origin": "lambda"})
    span = tracer.trace("aws.sqs", **args)
    if span:
        span.set_tags(tags)
    span.start = start_time
    if upstream_span:
        span.parent_id = upstream_span.span_id

    return span


def create_inferred_span_from_sns_event(event, context):
    event_record = get_first_record(event)
    sns_message = event_record.get("Sns")
    topic_arn = event_record.get("Sns", {}).get("TopicArn")
    topic_name = topic_arn.split(":")[-1]
    service_name = determine_service_name(
        service_mapping, topic_name, "lambda_sns", "sns"
    )
    tags = {
        "operation_name": "aws.sns",
        "resource_names": topic_name,
        "topicname": topic_name,
        "topic_arn": topic_arn,
        "message_id": sns_message.get("MessageId"),
        "type": sns_message.get("Type"),
    }

    # Subject not available in SNS => SQS scenario
    if "Subject" in sns_message and sns_message["Subject"]:
        tags["subject"] = sns_message.get("Subject")

    InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="async")
    sns_dt_format = "%Y-%m-%dT%H:%M:%S.%fZ"
    timestamp = event_record.get("Sns", {}).get("Timestamp")
    dt = datetime.strptime(timestamp, sns_dt_format)

    args = {
        "service": service_name,
        "resource": topic_name,
        "span_type": "web",
    }
    tracer.set_tags({"_dd.origin": "lambda"})
    span = tracer.trace("aws.sns", **args)
    if span:
        span.set_tags(tags)
    span.start = dt.replace(tzinfo=timezone.utc).timestamp()
    return span


def create_inferred_span_from_kinesis_event(event, context):
    event_record = get_first_record(event)
    event_source_arn = event_record.get("eventSourceARN")
    event_id = event_record.get("eventID")
    stream_name = event_source_arn.split(":")[-1]
    shard_id = event_id.split(":")[0]
    service_name = determine_service_name(
        service_mapping, stream_name, "lambda_kinesis", "kinesis"
    )
    tags = {
        "operation_name": "aws.kinesis",
        "resource_names": stream_name,
        "streamname": stream_name,
        "shardid": shard_id,
        "event_source_arn": event_source_arn,
        "event_id": event_id,
        "event_name": event_record.get("eventName"),
        "event_version": event_record.get("eventVersion"),
        "partition_key": event_record.get("kinesis", {}).get("partitionKey"),
    }
    InferredSpanInfo.set_tags(tags, tag_source="self", synchronicity="async")
    request_time_epoch = event_record.get("kinesis", {}).get(
        "approximateArrivalTimestamp"
    )

    args = {
        "service": service_name,
        "resource": stream_name,
        "span_type": "web",
    }
    tracer.set_tags({"_dd.origin": "lambda"})
    span = tracer.trace("aws.kinesis", **args)
    if span:
        span.set_tags(tags)
    span.start = request_time_epoch
    return span


def create_inferred_span_from_dynamodb_event(event, context):
    event_record = get_first_record(event)
    event_source_arn = event_record.get("eventSourceARN")
    table_name = event_source_arn.split("/")[1]
    service_name = determine_service_name(
        service_mapping, table_name, "lambda_dynamodb", "dynamodb"
    )
    dynamodb_message = event_record.get("dynamodb")
    tags = {
        "operation_name": "aws.dynamodb",
        "resource_names": table_name,
        "tablename": table_name,
        "event_source_arn": event_source_arn,
        "event_id": event_record.get("eventID"),
        "event_name": event_record.get("eventName"),
        "event_version": event_record.get("eventVersion"),
        "stream_view_type": dynamodb_message.get("StreamViewType"),
        "size_bytes": str(dynamodb_message.get("SizeBytes")),
    }
    InferredSpanInfo.set_tags(tags, synchronicity="async", tag_source="self")
    request_time_epoch = event_record.get("dynamodb", {}).get(
        "ApproximateCreationDateTime"
    )
    args = {
        "service": service_name,
        "resource": table_name,
        "span_type": "web",
    }
    tracer.set_tags({"_dd.origin": "lambda"})
    span = tracer.trace("aws.dynamodb", **args)
    if span:
        span.set_tags(tags)

    span.start = int(request_time_epoch)
    return span


def create_inferred_span_from_s3_event(event, context):
    event_record = get_first_record(event)
    bucket_name = event_record.get("s3", {}).get("bucket", {}).get("name")
    service_name = determine_service_name(
        service_mapping, bucket_name, "lambda_s3", "s3"
    )
    tags = {
        "operation_name": "aws.s3",
        "resource_names": bucket_name,
        "event_name": event_record.get("eventName"),
        "bucketname": bucket_name,
        "bucket_arn": event_record.get("s3", {}).get("bucket", {}).get("arn"),
        "object_key": event_record.get("s3", {}).get("object", {}).get("key"),
        "object_size": str(event_record.get("s3", {}).get("object", {}).get("size")),
        "object_etag": event_record.get("s3", {}).get("object", {}).get("eTag"),
    }
    InferredSpanInfo.set_tags(tags, synchronicity="async", tag_source="self")
    dt_format = "%Y-%m-%dT%H:%M:%S.%fZ"
    timestamp = event_record.get("eventTime")
    dt = datetime.strptime(timestamp, dt_format)

    args = {
        "service": service_name,
        "resource": bucket_name,
        "span_type": "web",
    }
    tracer.set_tags({"_dd.origin": "lambda"})
    span = tracer.trace("aws.s3", **args)
    if span:
        span.set_tags(tags)
    span.start = dt.replace(tzinfo=timezone.utc).timestamp()
    return span


def create_inferred_span_from_eventbridge_event(event, context):
    source = event.get("source")
    service_name = determine_service_name(
        service_mapping, source, "lambda_eventbridge", "eventbridge"
    )
    tags = {
        "operation_name": "aws.eventbridge",
        "resource_names": source,
        "detail_type": event.get("detail-type"),
    }
    InferredSpanInfo.set_tags(
        tags,
        synchronicity="async",
        tag_source="self",
    )
    dt_format = "%Y-%m-%dT%H:%M:%SZ"
    timestamp = event.get("time")
    dt = datetime.strptime(timestamp, dt_format)

    args = {
        "service": service_name,
        "resource": source,
        "span_type": "web",
    }
    tracer.set_tags({"_dd.origin": "lambda"})
    span = tracer.trace("aws.eventbridge", **args)
    if span:
        span.set_tags(tags)
    span.start = dt.replace(tzinfo=timezone.utc).timestamp()
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
            "span.name": "aws.lambda",
        }
    if is_proactive_init:
        tags["proactive_initialization"] = str(is_proactive_init).lower()
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
    if parent_span:
        span.parent_id = parent_span.span_id
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
