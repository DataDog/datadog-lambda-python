import logging
from typing import Any, Dict, List, Optional

from ddtrace.contrib.internal.trace_utils import _get_request_header_client_ip
from ddtrace.internal import core
from ddtrace.trace import Span

from datadog_lambda.trigger import (
    EventSubtypes,
    EventTypes,
    _EventSource,
    _http_event_types,
)

logger = logging.getLogger(__name__)


def _to_single_value_headers(request_headers: Dict[str, List[str]]) -> Dict[str, str]:
    """
    Convert multi-value headers to single-value headers.
    If a header has multiple values, the first value is used.
    """
    single_value_headers = {}
    for key, values in request_headers.items():
        if len(values) >= 1:
            single_value_headers[key] = values[0]
    return single_value_headers


def asm_start_request(
    span: Span,
    event: Dict[str, Any],
    event_source: _EventSource,
    trigger_tags: Dict[str, str],
):
    request_headers: Dict[str, str] = {}
    peer_ip: Optional[str] = None
    request_path_parameters: Optional[Dict[str, Any]] = None

    if event_source.event_type == EventTypes.ALB:
        headers = event.get("headers")
        multi_value_request_headers = event.get("multiValueHeaders")
        if multi_value_request_headers:
            request_headers = _to_single_value_headers(multi_value_request_headers)
        else:
            request_headers = headers or {}

        raw_uri = event.get("path")
        parsed_query = event.get("multiValueQueryStringParameters") or event.get(
            "queryStringParameters"
        )

    elif event_source.event_type == EventTypes.LAMBDA_FUNCTION_URL:
        request_headers = event.get("headers", {})
        peer_ip = event.get("requestContext", {}).get("http", {}).get("sourceIp")
        raw_uri = event.get("rawPath")
        parsed_query = event.get("queryStringParameters")

    elif event_source.event_type == EventTypes.API_GATEWAY:
        request_context = event.get("requestContext", {})
        request_path_parameters = event.get("pathParameters")

        if event_source.subtype == EventSubtypes.API_GATEWAY:
            request_headers = _to_single_value_headers(
                event.get("multiValueHeaders", {})
            )
            peer_ip = request_context.get("identity", {}).get("sourceIp")
            raw_uri = event.get("path")
            parsed_query = event.get("multiValueQueryStringParameters")

        elif event_source.subtype == EventSubtypes.HTTP_API:
            request_headers = event.get("headers", {})
            peer_ip = request_context.get("http", {}).get("sourceIp")
            raw_uri = event.get("rawPath")
            parsed_query = event.get("queryStringParameters")

        elif event_source.subtype == EventSubtypes.WEBSOCKET:
            request_headers = _to_single_value_headers(
                event.get("multiValueHeaders", {})
            )
            peer_ip = request_context.get("identity", {}).get("sourceIp")
            raw_uri = event.get("path")
            parsed_query = event.get("multiValueQueryStringParameters")

        else:
            return

    else:
        return

    body = event.get("body")
    is_base64_encoded = event.get("isBase64Encoded", False)

    request_ip = _get_request_header_client_ip(request_headers, peer_ip, True)
    if request_ip is not None:
        span.set_tag_str("http.client_ip", request_ip)
        span.set_tag_str("network.client.ip", request_ip)

    core.dispatch(
        "aws_lambda.start_request",
        (
            span,
            request_headers,
            request_ip,
            body,
            is_base64_encoded,
            raw_uri,
            trigger_tags.get("http.route"),
            trigger_tags.get("http.method"),
            parsed_query,
            request_path_parameters,
        ),
    )


def asm_start_response(
    span: Span,
    status_code: str,
    event_source: _EventSource,
    response: Dict[str, Any],
):
    if event_source.event_type not in _http_event_types:
        return

    response_headers = response.get("headers", {})
    if not isinstance(response_headers, dict):
        response_headers = {}

    core.dispatch(
        "aws_lambda.start_response",
        (
            span,
            status_code,
            response_headers,
        ),
    )
