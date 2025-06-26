import json
import pytest
from unittest.mock import MagicMock, patch

from datadog_lambda.asm import asm_start_request, asm_start_response
from datadog_lambda.trigger import parse_event_source, extract_trigger_tags
from tests.utils import get_mock_context

event_samples = "tests/event_samples/"


# Test cases for ASM start request
ASM_START_REQUEST_TEST_CASES = [
    (
        "application_load_balancer",
        "application-load-balancer.json",
        "72.12.164.125",
        "/lambda",
        "GET",
        "",
        False,
        {"query": "1234ABCD"},
        None,
        None,
    ),
    (
        "application_load_balancer_multivalue_headers",
        "application-load-balancer-mutivalue-headers.json",
        "72.12.164.125",
        "/lambda",
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
        "/path/to/resource",
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
        True,
    ),
    (
        "application_load_balancer_multivalue_headers",
        "application-load-balancer-mutivalue-headers.json",
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
        True,
    ),
    (
        "non_http_event_s3",
        "s3.json",
        {"statusCode": 200},
        "200",
        {},
        False,  # Should not dispatch for non-HTTP events
    ),
    (
        "api_gateway_v2_string_response",
        "api-gateway-v2-parametrized.json",
        "Hello, World!",
        "200",
        {"content-type": "application/json"},
        True,
    ),
    (
        "api_gateway_v2_dict_response",
        "api-gateway-v2-parametrized.json",
        {"message": "Hello, World!"},
        "200",
        {"content-type": "application/json"},
        True,
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
        mock_span.set_tag_str.assert_any_call("http.client_ip", expected_ip)
        mock_span.set_tag_str.assert_any_call("network.client.ip", expected_ip)


@pytest.mark.parametrize(
    "name,event_file,response,status_code,expected_headers,should_dispatch",
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
        # Verify core.dispatch was called
        mock_core.dispatch.assert_called_once()
        call_args = mock_core.dispatch.call_args
        assert call_args[0][0] == "aws_lambda.start_response"

        # Extract the dispatched arguments
        dispatch_args = call_args[0][1]
        span, response_status_code, response_headers = dispatch_args

        assert span == mock_span
        assert response_status_code == status_code
        assert response_headers == expected_headers
    else:
        # Verify core.dispatch was not called for non-HTTP events
        mock_core.dispatch.assert_not_called()
