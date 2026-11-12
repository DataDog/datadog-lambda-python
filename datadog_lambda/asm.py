import logging
import os
import re
import urllib.parse
from copy import deepcopy
from typing import Any, Dict, List, Optional, Union

from ddtrace.contrib.internal.trace_utils import _get_request_header_client_ip
from ddtrace.internal import core
from ddtrace.internal.utils import get_blocked
from ddtrace.internal.utils import http as http_utils
from ddtrace.trace import Span

from datadog_lambda.config import config
from datadog_lambda.trigger import (
    EventSubtypes,
    EventTypes,
    _EventSource,
    _http_event_types,
)

logger = logging.getLogger(__name__)

AWS_ACCESS_KEY_ID_TAG = "aws.lambda.access_key_id"
_AWS_ACCESS_KEY_ID_PATTERN = re.compile(r"(ASIA|AKIA)[A-Z0-9]{16}")
_UNSET = object()
_aws_access_key_id: Any = _UNSET


def _get_aws_access_key_id() -> Optional[str]:
    """Return the execution environment's AWS access key ID, read once.

    Only AWS_ACCESS_KEY_ID is read: the secret key and the session token are
    never touched. The read happens at the first monitored invocation, so on
    SnapStart it runs after restore, never before the snapshot.
    """
    global _aws_access_key_id
    if _aws_access_key_id is _UNSET:
        value = os.environ.get("AWS_ACCESS_KEY_ID", "")
        if _AWS_ACCESS_KEY_ID_PATTERN.fullmatch(value):
            _aws_access_key_id = value
        else:
            _aws_access_key_id = None
            logger.debug(
                "AWS_ACCESS_KEY_ID is empty or malformed, %s is not set",
                AWS_ACCESS_KEY_ID_TAG,
            )
    return _aws_access_key_id


def _to_single_value_headers(headers: Dict[str, List[str]]) -> Dict[str, str]:
    """
    Convert multi-value headers to single-value headers.
    If a header has multiple values, join them with commas.
    """
    single_value_headers = {}
    for key, values in headers.items():
        single_value_headers[key] = ", ".join(values)
    return single_value_headers


def _merge_single_and_multi_value_headers(
    single_value_headers: Dict[str, str],
    multi_value_headers: Dict[str, List[str]],
):
    """
    Merge single-value headers with multi-value headers.
    If a header exists in both, we merge them removing duplicates
    """
    merged_headers = deepcopy(multi_value_headers)
    for key, value in single_value_headers.items():
        if key not in merged_headers:
            merged_headers[key] = [value]
        elif value not in merged_headers[key]:
            merged_headers[key].append(value)
    return _to_single_value_headers(merged_headers)


def asm_set_context(event_source: _EventSource):
    """Add asm specific items to the ExecutionContext.

    This allows the AppSecSpanProcessor to know information about the event
    at the moment the span is created and skip it when not relevant.
    """

    if event_source.event_type not in _http_event_types:
        core.set_item("appsec_skip_next_lambda_event", True)


def asm_start_request(
    span: Span,
    event: Dict[str, Any],
    event_source: _EventSource,
    trigger_tags: Dict[str, str],
):
    if event_source.event_type not in _http_event_types:
        return

    request_headers: Dict[str, str] = {}
    peer_ip: Optional[str] = None
    request_path_parameters: Optional[Dict[str, Any]] = None
    route: Optional[str] = None

    if event_source.event_type == EventTypes.ALB:
        raw_uri = event.get("path")

        if event_source.subtype == EventSubtypes.ALB:
            request_headers = event.get("headers", {})
            parsed_query = event.get("queryStringParameters")
        if event_source.subtype == EventSubtypes.ALB_MULTI_VALUE_HEADERS:
            request_headers = _to_single_value_headers(
                event.get("multiValueHeaders", {})
            )
            parsed_query = event.get("multiValueQueryStringParameters")

    elif event_source.event_type == EventTypes.LAMBDA_FUNCTION_URL:
        request_headers = event.get("headers", {})
        peer_ip = event.get("requestContext", {}).get("http", {}).get("sourceIp")
        raw_uri = event.get("rawPath")
        parsed_query = event.get("queryStringParameters")

    elif event_source.event_type == EventTypes.API_GATEWAY:
        request_context = event.get("requestContext", {})
        request_path_parameters = event.get("pathParameters")
        route = trigger_tags.get("http.route")

        if event_source.subtype == EventSubtypes.API_GATEWAY:
            request_headers = event.get("headers", {})
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

    if config.appsec_aws_access_key_id_enabled:
        access_key_id = _get_aws_access_key_id()
        if access_key_id:
            span.set_tag(AWS_ACCESS_KEY_ID_TAG, access_key_id)

    body = event.get("body")
    is_base64_encoded = event.get("isBase64Encoded", False)

    request_ip = _get_request_header_client_ip(request_headers, peer_ip, True)
    if request_ip is not None:
        span.set_tag("http.client_ip", request_ip)
        span.set_tag("network.client.ip", request_ip)

    # Encode the parsed query and append it to reconstruct the original raw URI expected by AppSec.
    if parsed_query:
        try:
            encoded_query = urllib.parse.urlencode(parsed_query, doseq=True)
            raw_uri += "?" + encoded_query  # type: ignore
        except Exception:
            pass

    core.dispatch(
        # The matching listener is registered in ddtrace.appsec._handlers
        "aws_lambda.start_request",
        (
            span,
            request_headers,
            request_ip,
            body,
            is_base64_encoded,
            raw_uri,
            route,
            trigger_tags.get("http.method"),
            parsed_query,
            request_path_parameters,
        ),
    )


def asm_start_response(
    span: Span,
    status_code: str,
    event_source: _EventSource,
    response: Union[Dict[str, Any], str, None],
):
    if event_source.event_type not in _http_event_types:
        return

    if isinstance(response, dict) and (
        "headers" in response or "multiValueHeaders" in response
    ):
        headers = response.get("headers", {})
        multi_value_request_headers = response.get("multiValueHeaders")
        if isinstance(multi_value_request_headers, dict) and isinstance(headers, dict):
            response_headers = _merge_single_and_multi_value_headers(
                headers, multi_value_request_headers
            )
        elif isinstance(headers, dict):
            response_headers = headers
        else:
            response_headers = {
                "content-type": "application/json",
            }
    else:
        response_headers = {
            "content-type": "application/json",
        }

    core.dispatch(
        # The matching listener is registered in ddtrace.appsec._handlers
        "aws_lambda.start_response",
        (
            span,
            status_code,
            response_headers,
        ),
    )

    if isinstance(response, dict) and "statusCode" in response:
        body = response.get("body")
    else:
        body = response

    core.dispatch(
        # The matching listener is registered in ddtrace.appsec._handlers
        "aws_lambda.parse_body",
        (body,),
    )


def get_asm_blocked_response(
    event_source: _EventSource,
) -> Optional[Dict[str, Any]]:
    """Get the blocked response for the given event source."""
    if event_source.event_type not in _http_event_types:
        return None

    blocked = get_blocked()
    if not blocked:
        return None

    desired_type = blocked.get("type", "auto")
    if desired_type == "none":
        content_type = "text/plain; charset=utf-8"
        content = ""
    else:
        content_type = blocked.get("content-type", "application/json")
        content = http_utils._get_blocked_template(
            content_type, blocked.get("block_id", "default")
        )

    response = {
        "statusCode": blocked.get("status_code", 403),
        "body": content,
        "isBase64Encoded": False,
    }

    needs_multi_value_headers = event_source.equals(
        EventTypes.ALB, EventSubtypes.ALB_MULTI_VALUE_HEADERS
    )

    if needs_multi_value_headers:
        response["multiValueHeaders"] = {
            "content-type": [content_type],
        }
        if "location" in blocked:
            response["multiValueHeaders"]["location"] = [blocked["location"]]
    else:
        response["headers"] = {
            "content-type": content_type,
        }
        if "location" in blocked:
            response["headers"]["location"] = blocked["location"]

    return response
