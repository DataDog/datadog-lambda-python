import json
import pytest
from unittest.mock import MagicMock, patch

from ddtrace.trace import Span

from datadog_lambda import asm
from datadog_lambda.asm import (
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


# Tests for the AWS access key ID tag (RFC "CADR for AWS Lambda", D1 to D8).
FAKE_ACCESS_KEY_ID = "ASIAEXAMPLE000000001"
CANARY_SECRET = "canary-secret-7f3b9c1e"
CANARY_TOKEN = "canary-token-2d8a6e4f"


@pytest.fixture
def access_key_env(monkeypatch):
    monkeypatch.setattr(asm, "_aws_access_key_id", asm._UNREAD)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", FAKE_ACCESS_KEY_ID)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", CANARY_SECRET)
    monkeypatch.setenv("AWS_SESSION_TOKEN", CANARY_TOKEN)
    monkeypatch.setenv("DD_APPSEC_AWS_ACCESS_KEY_ID_ENABLED", "true")
    return monkeypatch


def _start_request(file="lambda-url.json"):
    with open(event_samples + file, "r") as f:
        event = json.load(f)
    span = Span("aws.lambda")
    with patch("datadog_lambda.asm.core"):
        asm_start_request(
            span, event, parse_event_source(event), extract_trigger_tags(event, ctx)
        )
    return span


ctx = get_mock_context()


@pytest.mark.parametrize("file", [case[1] for case in ASM_START_REQUEST_TEST_CASES])
def test_access_key_id_tag_on_http_events(access_key_env, file):
    # S1: every HTTP event type that AppSec monitors carries the tag.
    span = _start_request(file)
    assert span.get_tag(asm.AWS_ACCESS_KEY_ID_TAG) == FAKE_ACCESS_KEY_ID


@pytest.mark.parametrize("value", [None, "false", "0", "no"])
def test_access_key_id_tag_feature_off(access_key_env, value):
    # S2: unset or false gives no tag, and the variable is not read.
    if value is None:
        access_key_env.delenv("DD_APPSEC_AWS_ACCESS_KEY_ID_ENABLED")
    else:
        access_key_env.setenv("DD_APPSEC_AWS_ACCESS_KEY_ID_ENABLED", value)
    span = _start_request()
    assert span.get_tag(asm.AWS_ACCESS_KEY_ID_TAG) is None
    assert asm._aws_access_key_id is asm._UNREAD


@pytest.mark.parametrize("file", [case[1] for case in ASM_START_REQUEST_TEST_CASES])
def test_access_key_id_tag_never_carries_secret_or_token(access_key_env, file):
    # S3: neither canary appears anywhere on the span.
    span = _start_request(file)
    serialized = json.dumps(span.get_tags()) + json.dumps(span.get_metrics())
    assert CANARY_SECRET not in serialized
    assert CANARY_TOKEN not in serialized


def test_access_key_id_read_ignores_secret_and_token(access_key_env):
    # D1: only AWS_ACCESS_KEY_ID is read from the environment.
    env = {
        "AWS_ACCESS_KEY_ID": FAKE_ACCESS_KEY_ID,
        "AWS_SECRET_ACCESS_KEY": CANARY_SECRET,
        "AWS_SESSION_TOKEN": CANARY_TOKEN,
    }
    with patch("datadog_lambda.asm.os.environ") as environ:
        environ.get.side_effect = lambda key, default=None: env.get(key, default)
        assert asm._get_aws_access_key_id() == FAKE_ACCESS_KEY_ID
    read_keys = {c.args[0] for c in environ.get.call_args_list}
    # The initialization type is read through config, for the SnapStart check.
    assert read_keys <= {"AWS_ACCESS_KEY_ID", "AWS_LAMBDA_INITIALIZATION_TYPE"}
    assert "AWS_SECRET_ACCESS_KEY" not in str(environ.mock_calls)
    assert "AWS_SESSION_TOKEN" not in str(environ.mock_calls)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "ASIAEXAMPLE00000000",  # 15 characters after the prefix
        "ASIAEXAMPLE0000000011",  # 17 characters after the prefix
        "asiaexample000000001",  # lower case
        "ABIAEXAMPLE000000001",  # unknown prefix
        "ASIAEXAMPLE00000000!",
        "ASIAEXAMPLE000000001\n",  # trailing newline
        " ASIAEXAMPLE000000001",
    ],
)
def test_access_key_id_tag_empty_or_malformed(access_key_env, caplog, value):
    # S5: no tag and nothing logged above debug.
    access_key_env.setenv("AWS_ACCESS_KEY_ID", value)
    with caplog.at_level("DEBUG", logger="datadog_lambda.asm"):
        span = _start_request()
    assert span.get_tag(asm.AWS_ACCESS_KEY_ID_TAG) is None
    assert all(r.levelname == "DEBUG" for r in caplog.records)
    assert all(value not in r.getMessage() for r in caplog.records if value)


def test_access_key_id_tag_missing(access_key_env, caplog):
    # S5: missing variable.
    access_key_env.delenv("AWS_ACCESS_KEY_ID")
    with caplog.at_level("DEBUG", logger="datadog_lambda.asm"):
        span = _start_request()
    assert span.get_tag(asm.AWS_ACCESS_KEY_ID_TAG) is None
    assert all(r.levelname == "DEBUG" for r in caplog.records)


def test_access_key_id_tag_akia_prefix(access_key_env):
    # D3: long-term keys (AKIA) are valid too.
    access_key_env.setenv("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE000000001")
    span = _start_request()
    assert span.get_tag(asm.AWS_ACCESS_KEY_ID_TAG) == "AKIAEXAMPLE000000001"


def test_access_key_id_read_once(access_key_env):
    # S6 and D2: same value on two invocations, the variable is read once.
    with patch(
        "datadog_lambda.asm._read_aws_access_key_id", wraps=asm._read_aws_access_key_id
    ) as read:
        first = _start_request()
        access_key_env.setenv("AWS_ACCESS_KEY_ID", "ASIAEXAMPLE000000002")
        second = _start_request()
    assert read.call_count == 1
    assert first.get_tag(asm.AWS_ACCESS_KEY_ID_TAG) == FAKE_ACCESS_KEY_ID
    assert second.get_tag(asm.AWS_ACCESS_KEY_ID_TAG) == FAKE_ACCESS_KEY_ID


def test_access_key_id_invalid_value_is_cached(access_key_env):
    # D2: a missing value is cached too, so there is no read per invocation.
    access_key_env.setenv("AWS_ACCESS_KEY_ID", "")
    _start_request()
    access_key_env.setenv("AWS_ACCESS_KEY_ID", FAKE_ACCESS_KEY_ID)
    span = _start_request()
    assert span.get_tag(asm.AWS_ACCESS_KEY_ID_TAG) is None


def test_access_key_id_tag_snapstart(access_key_env):
    # D2: on SnapStart the environment predates the snapshot: no tag.
    access_key_env.setenv("AWS_LAMBDA_INITIALIZATION_TYPE", "snap-start")
    span = _start_request()
    assert span.get_tag(asm.AWS_ACCESS_KEY_ID_TAG) is None


@pytest.mark.parametrize(
    "init_type", ["on-demand", "provisioned-concurrency", "lambda-managed-instances"]
)
def test_access_key_id_tag_other_initialization_types(access_key_env, init_type):
    access_key_env.setenv("AWS_LAMBDA_INITIALIZATION_TYPE", init_type)
    span = _start_request()
    assert span.get_tag(asm.AWS_ACCESS_KEY_ID_TAG) == FAKE_ACCESS_KEY_ID


@pytest.mark.parametrize(
    "file", ["sqs-batch.json", "eventbridge-custom.json", "sns-batch.json"]
)
def test_access_key_id_tag_not_on_non_http_events(access_key_env, file):
    # D4: AppSec does not monitor non-HTTP events, so they carry no tag.
    span = _start_request(file)
    assert span.get_tag(asm.AWS_ACCESS_KEY_ID_TAG) is None


def test_access_key_id_tag_set_before_dispatch(access_key_env):
    # S7: the tag is on the span before the WAF runs, so a span that AppSec
    # blocks or flags at request time carries it.
    with open(event_samples + "lambda-url.json", "r") as f:
        event = json.load(f)
    event["rawQueryString"] = "file=/proc/self/environ"
    event["queryStringParameters"] = {"file": "/proc/self/environ"}
    span = Span("aws.lambda")
    seen = {}

    def dispatch(name, args):
        seen[name] = args[0].get_tag(asm.AWS_ACCESS_KEY_ID_TAG)

    with patch("datadog_lambda.asm.core") as mock_core:
        mock_core.dispatch.side_effect = dispatch
        asm_start_request(
            span, event, parse_event_source(event), extract_trigger_tags(event, ctx)
        )
    assert seen == {"aws_lambda.start_request": FAKE_ACCESS_KEY_ID}
