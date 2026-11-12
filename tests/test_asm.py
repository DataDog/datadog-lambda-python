import json
import logging
import os
import pytest
from unittest.mock import MagicMock, patch

from datadog_lambda.asm import (
    AWS_ACCESS_KEY_ID_TAG,
    asm_start_request,
    asm_start_response,
    get_asm_blocked_response,
)
from datadog_lambda.trigger import (
    EventSubtypes,
    EventTypes,
    _EventSource,
    extract_trigger_tags,
    parse_event_source,
)
from tests.utils import get_mock_context

event_samples = "tests/event_samples/"


# Test cases for ASM start request
ASM_START_REQUEST_TEST_CASES = [
    (
        "application_load_balancer",
        "application-load-balancer.json",
        "72.12.164.125",
        "/lambda?query=1234ABCD",
        "GET",
        "",
        False,
        {"query": "1234ABCD"},
        None,
        None,
    ),
    (
        "application_load_balancer_multivalue_headers",
        "application-load-balancer-multivalue-headers.json",
        "72.12.164.125",
        "/lambda?query=1234ABCD",
        "GET",
        "",
        False,
        {"query": "1234ABCD"},
        None,
        None,
    ),
    (
        "lambda_function_url",
        "lambda-url.json",
        "71.195.30.42",
        "/",
        "GET",
        None,
        False,
        None,
        None,
        None,
    ),
    (
        "api_gateway",
        "api-gateway.json",
        "127.0.0.1",
        "/path/to/resource?foo=bar",
        "POST",
        "eyJ0ZXN0IjoiYm9keSJ9",
        True,
        {"foo": ["bar"]},
        {"proxy": "/path/to/resource"},
        "/{proxy+}",
    ),
    (
        "api_gateway_v2_parametrized",
        "api-gateway-v2-parametrized.json",
        "76.115.124.192",
        "/user/42",
        "GET",
        None,
        False,
        None,
        {"id": "42"},
        "/user/{id}",
    ),
    (
        "api_gateway_websocket",
        "api-gateway-websocket-default.json",
        "38.122.226.210",
        None,
        None,
        '"What\'s good in the hood?"',
        False,
        None,
        None,
        None,
    ),
]


# Test cases for ASM start response
ASM_START_RESPONSE_TEST_CASES = [
    (
        "application_load_balancer",
        "application-load-balancer.json",
        {
            "statusCode": 200,
            "headers": {"Content-Type": "text/html"},
        },
        "200",
        {"Content-Type": "text/html"},
        None,
        True,
    ),
    (
        "application_load_balancer_multivalue_headers",
        "application-load-balancer-multivalue-headers.json",
        {
            "statusCode": 404,
            "multiValueHeaders": {
                "Content-Type": ["text/plain"],
                "X-Error": ["Not Found"],
            },
        },
        "404",
        {
            "Content-Type": "text/plain",
            "X-Error": "Not Found",
        },
        None,
        True,
    ),
    (
        "lambda_function_url",
        "lambda-url.json",
        {
            "statusCode": 201,
            "headers": {
                "Location": "/user/123",
                "Content-Type": "application/json",
            },
        },
        "201",
        {
            "Location": "/user/123",
            "Content-Type": "application/json",
        },
        None,
        True,
    ),
    (
        "api_gateway",
        "api-gateway.json",
        {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "X-Custom-Header": "test-value",
            },
            "body": '{"message": "success"}',
        },
        "200",
        {
            "Content-Type": "application/json",
            "X-Custom-Header": "test-value",
        },
        '{"message": "success"}',
        True,
    ),
    (
        "api_gateway_v2_parametrized",
        "api-gateway-v2-parametrized.json",
        {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
        },
        "200",
        {"Content-Type": "application/json"},
        None,
        True,
    ),
    (
        "api_gateway_websocket",
        "api-gateway-websocket-default.json",
        {
            "statusCode": 200,
            "headers": {"Content-Type": "text/plain"},
        },
        "200",
        {"Content-Type": "text/plain"},
        None,
        True,
    ),
    (
        "non_http_event_s3",
        "s3.json",
        {"statusCode": 200},
        "200",
        {},
        None,
        False,  # Should not dispatch for non-HTTP events
    ),
    (
        "api_gateway_v2_string_response",
        "api-gateway-v2-parametrized.json",
        "Hello, World!",
        "200",
        {"content-type": "application/json"},
        "Hello, World!",
        True,
    ),
    (
        "api_gateway_v2_dict_response",
        "api-gateway-v2-parametrized.json",
        {"message": "Hello, World!"},
        "200",
        {"content-type": "application/json"},
        {"message": "Hello, World!"},
        True,
    ),
]

ASM_BLOCKED_RESPONSE_TEST_CASES = [
    # JSON blocking response
    (
        {"status_code": 403, "type": "auto", "content-type": "application/json"},
        403,
        {"content-type": "application/json"},
    ),
    # HTML blocking response
    (
        {
            "status_code": 401,
            "type": "html",
            "content-type": "text/html",
        },
        401,
        {"content-type": "text/html"},
    ),
    # Plain text redirect response
    (
        {"status_code": 301, "type": "none", "location": "https://example.com/blocked"},
        301,
        {
            "content-type": "text/plain; charset=utf-8",
            "location": "https://example.com/blocked",
        },
    ),
    # Default to content-type application/json and status code 403 when not provided
    (
        {"type": "auto"},
        403,
        {"content-type": "application/json"},
    ),
]


@pytest.mark.parametrize(
    "name,file,expected_ip,expected_uri,expected_method,expected_body,expected_base64,expected_query,expected_path_params,expected_route",
    ASM_START_REQUEST_TEST_CASES,
)
@patch("datadog_lambda.asm.core")
def test_asm_start_request_parametrized(
    mock_core,
    name,
    file,
    expected_ip,
    expected_uri,
    expected_method,
    expected_body,
    expected_base64,
    expected_query,
    expected_path_params,
    expected_route,
):
    """Test ASM start request for various HTTP event types using parametrization"""
    mock_span = MagicMock()
    ctx = get_mock_context()

    # Reset mock for each test
    mock_core.reset_mock()
    mock_span.reset_mock()

    test_file = event_samples + file
    with open(test_file, "r") as f:
        event = json.load(f)

    event_source = parse_event_source(event)
    trigger_tags = extract_trigger_tags(event, ctx)

    asm_start_request(mock_span, event, event_source, trigger_tags)

    # Verify core.dispatch was called
    mock_core.dispatch.assert_called_once()
    call_args = mock_core.dispatch.call_args
    dispatch_args = call_args[0][1]
    (
        span,
        request_headers,
        request_ip,
        body,
        is_base64_encoded,
        raw_uri,
        http_route,
        http_method,
        parsed_query,
        request_path_parameters,
    ) = dispatch_args

    # Common assertions
    assert span == mock_span
    assert isinstance(request_headers, dict)

    # Specific assertions based on test case
    assert request_ip == expected_ip
    assert raw_uri == expected_uri
    assert http_method == expected_method
    assert body == expected_body
    assert is_base64_encoded == expected_base64

    if expected_query is not None:
        assert parsed_query == expected_query
    else:
        assert parsed_query is None

    if expected_path_params is not None:
        assert request_path_parameters == expected_path_params
    else:
        assert request_path_parameters is None

    # Check route is correctly extracted and passed
    assert http_route == expected_route

    # Check IP tags were set if IP is present
    if expected_ip:
        mock_span.set_tag.assert_any_call("http.client_ip", expected_ip)
        mock_span.set_tag.assert_any_call("network.client.ip", expected_ip)


@pytest.mark.parametrize(
    "name,event_file,response,status_code,expected_headers,expected_body,should_dispatch",
    ASM_START_RESPONSE_TEST_CASES,
)
@patch("datadog_lambda.asm.core")
def test_asm_start_response_parametrized(
    mock_core,
    name,
    event_file,
    response,
    status_code,
    expected_headers,
    expected_body,
    should_dispatch,
):
    """Test ASM start response for various HTTP event types using parametrization"""
    mock_span = MagicMock()

    # Reset mock for each test
    mock_core.reset_mock()
    mock_span.reset_mock()

    test_file = event_samples + event_file
    with open(test_file, "r") as f:
        event = json.load(f)

    event_source = parse_event_source(event)

    asm_start_response(mock_span, status_code, event_source, response)

    if should_dispatch:
        assert mock_core.dispatch.call_count == 2

        assert mock_core.dispatch.call_args_list[0].args == (
            "aws_lambda.start_response",
            (mock_span, status_code, expected_headers),
        )

        assert mock_core.dispatch.call_args_list[1].args == (
            "aws_lambda.parse_body",
            (expected_body,),
        )
    else:
        # Verify core.dispatch was not called for non-HTTP events
        mock_core.dispatch.assert_not_called()


@pytest.mark.parametrize(
    "blocked_config, expected_status, expected_headers",
    ASM_BLOCKED_RESPONSE_TEST_CASES,
)
@patch("datadog_lambda.asm.get_blocked")
def test_get_asm_blocked_response_blocked(
    mock_get_blocked,
    blocked_config,
    expected_status,
    expected_headers,
):
    mock_get_blocked.return_value = blocked_config
    event_source = _EventSource(event_type=EventTypes.API_GATEWAY)
    response = get_asm_blocked_response(event_source)
    assert response["statusCode"] == expected_status
    assert response["headers"] == expected_headers
    assert "multiValueHeaders" not in response


@patch("datadog_lambda.asm.get_blocked")
def test_get_asm_blocked_response_blocked_multi_value_headers(
    mock_get_blocked,
):
    # HTML blocking response
    mock_get_blocked.return_value = {
        "status_code": 401,
        "type": "html",
        "content-type": "text/html",
    }

    event_source = _EventSource(EventTypes.ALB, EventSubtypes.ALB_MULTI_VALUE_HEADERS)
    response = get_asm_blocked_response(event_source)
    assert response["statusCode"] == 401
    assert response["multiValueHeaders"] == {"content-type": ["text/html"]}
    assert "headers" not in response


@patch("datadog_lambda.asm.get_blocked")
def test_get_asm_blocked_response_not_blocked(
    mock_get_blocked,
):
    mock_get_blocked.return_value = None
    event_source = _EventSource(event_type=EventTypes.API_GATEWAY)
    response = get_asm_blocked_response(event_source)
    assert response is None


ACCESS_KEY_ID = "ASIAEXAMPLE000000001"
SECRET_CANARY = "canary-secret-ee3f9c1b"
TOKEN_CANARY = "canary-token-7d41a0c2"


@pytest.fixture
def aws_credentials(monkeypatch):
    import datadog_lambda.asm as asm

    monkeypatch.setattr(asm, "_aws_access_key_id", asm._UNSET)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", ACCESS_KEY_ID)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", SECRET_CANARY)
    monkeypatch.setenv("AWS_SESSION_TOKEN", TOKEN_CANARY)
    return monkeypatch


def _start_request(file="lambda-url.json"):
    with open(event_samples + file, "r") as f:
        event = json.load(f)
    span = MagicMock()
    with patch("datadog_lambda.asm.core"):
        asm_start_request(
            span,
            event,
            parse_event_source(event),
            extract_trigger_tags(event, get_mock_context()),
        )
    return span


def _access_key_tag_calls(span):
    return [
        c for c in span.set_tag.call_args_list if c.args[0] == AWS_ACCESS_KEY_ID_TAG
    ]


@pytest.mark.parametrize(
    "file",
    [
        "lambda-url.json",
        "api-gateway.json",
        "http-api.json",
        "application-load-balancer.json",
    ],
)
def test_access_key_id_tag_set_when_enabled(aws_credentials, file):
    aws_credentials.setenv("DD_APPSEC_AWS_ACCESS_KEY_ID_ENABLED", "true")
    span = _start_request(file)
    span.set_tag.assert_any_call(AWS_ACCESS_KEY_ID_TAG, ACCESS_KEY_ID)
    assert len(_access_key_tag_calls(span)) == 1


@pytest.mark.parametrize("value", [None, "false", "0"])
def test_access_key_id_tag_off_by_default(aws_credentials, value):
    if value is not None:
        aws_credentials.setenv("DD_APPSEC_AWS_ACCESS_KEY_ID_ENABLED", value)
    span = _start_request()
    assert _access_key_tag_calls(span) == []


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ASIA",
        "XXXXEXAMPLE000000001",
        "asiaexample000000001",
        "ASIAEXAMPLE0000000012",
        "ASIAEXAMPLE000000001\n",
    ],
)
def test_access_key_id_tag_not_set_for_malformed_value(aws_credentials, value, caplog):
    aws_credentials.setenv("DD_APPSEC_AWS_ACCESS_KEY_ID_ENABLED", "true")
    aws_credentials.setenv("AWS_ACCESS_KEY_ID", value)
    with caplog.at_level(logging.DEBUG, logger="datadog_lambda.asm"):
        span = _start_request()
    assert _access_key_tag_calls(span) == []
    assert all(r.levelno <= logging.DEBUG for r in caplog.records)


def test_access_key_id_tag_not_set_when_variable_missing(aws_credentials):
    aws_credentials.setenv("DD_APPSEC_AWS_ACCESS_KEY_ID_ENABLED", "true")
    aws_credentials.delenv("AWS_ACCESS_KEY_ID")
    span = _start_request()
    assert _access_key_tag_calls(span) == []


def test_access_key_id_read_once(aws_credentials):
    aws_credentials.setenv("DD_APPSEC_AWS_ACCESS_KEY_ID_ENABLED", "true")
    first = _start_request()
    aws_credentials.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE000000002")
    second = _start_request()
    first.set_tag.assert_any_call(AWS_ACCESS_KEY_ID_TAG, ACCESS_KEY_ID)
    second.set_tag.assert_any_call(AWS_ACCESS_KEY_ID_TAG, ACCESS_KEY_ID)


def test_access_key_id_tag_not_set_for_non_http_event(aws_credentials):
    aws_credentials.setenv("DD_APPSEC_AWS_ACCESS_KEY_ID_ENABLED", "true")
    span = _start_request("sqs-batch.json")
    assert _access_key_tag_calls(span) == []


class _GuardedEnviron(dict):
    """Fails the test if the secret access key or the session token is read"""

    FORBIDDEN = ("AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")

    def __getitem__(self, key):
        assert key not in self.FORBIDDEN, f"{key} was read"
        return super().__getitem__(key)

    def get(self, key, default=None):
        assert key not in self.FORBIDDEN, f"{key} was read"
        return super().get(key, default)


def test_access_key_id_never_reads_secret_or_token(aws_credentials, caplog):
    import datadog_lambda.asm as asm

    aws_credentials.setenv("DD_APPSEC_AWS_ACCESS_KEY_ID_ENABLED", "true")
    aws_credentials.setattr(asm.os, "environ", _GuardedEnviron(os.environ))
    with caplog.at_level(logging.DEBUG):
        span = _start_request()
    span.set_tag.assert_any_call(AWS_ACCESS_KEY_ID_TAG, ACCESS_KEY_ID)
    recorded = repr(span.mock_calls) + caplog.text
    assert SECRET_CANARY not in recorded
    assert TOKEN_CANARY not in recorded
