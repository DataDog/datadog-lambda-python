import pytest

from datadog_lambda.config import config, _get_env


@pytest.fixture
def setenv(monkeypatch):
    def set_env(key, value):
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)

    return set_env


def _test_as_bool(env_key, conf_key, default):
    return (
        (env_key, conf_key, None, default),
        (env_key, conf_key, "", False),
        (env_key, conf_key, "true", True),
        (env_key, conf_key, "TRUE", True),
        (env_key, conf_key, "false", False),
        (env_key, conf_key, "FALSE", False),
        (env_key, conf_key, "1", True),  # CHANGED
        (env_key, conf_key, "0", False),
        (env_key, conf_key, "purple", False),
    )


def _test_int(env_key, conf_key, default):
    return (
        (env_key, conf_key, None, default),
        (env_key, conf_key, "", default),
        (env_key, conf_key, "5", 5),
        (env_key, conf_key, "0", 0),
        (env_key, conf_key, "2.5", default),
        (env_key, conf_key, "-1", -1),
        (env_key, conf_key, "purple", default),
    )


def _test_as_list(env_key, conf_key, default):
    return (
        (env_key, conf_key, None, default.split(",")),
        (env_key, conf_key, "", []),
        (env_key, conf_key, " ", []),
        (env_key, conf_key, ",", []),
        (env_key, conf_key, " , ", []),
        (env_key, conf_key, "a", ["a"]),
        (env_key, conf_key, "a,", ["a"]),
        (env_key, conf_key, "a, ", ["a"]),
        (env_key, conf_key, "a,b", ["a", "b"]),
        (env_key, conf_key, "a, b", ["a", "b"]),
    )


_test_config_from_environ = (
    *_test_as_bool("DD_FLUSH_TO_LOG", "flush_to_log", default=False),
    *_test_as_bool("DD_LOGS_INJECTION", "logs_injection", default=True),
    *_test_as_bool("DD_TRACE_ENABLED", "trace_enabled", default=True),
    *_test_as_bool("DD_COLD_START_TRACING", "cold_start_tracing", default=True),
    *_test_as_bool("DD_TRACE_MANAGED_SERVICES", "make_inferred_span", default=True),
    *_test_as_bool(
        "DD_ENCODE_AUTHORIZER_CONTEXT", "encode_authorizer_context", default=True
    ),
    *_test_as_bool(
        "DD_DECODE_AUTHORIZER_CONTEXT", "decode_authorizer_context", default=True
    ),
    *_test_as_bool("DD_FLUSH_IN_THREAD", "flush_in_thread", default=False),
    *_test_as_bool("DD_ENHANCED_METRICS", "enhanced_metrics_enabled", default=True),
    *_test_as_bool("DD_INTEGRATION_TEST", "integration_test", default=False),
    *_test_as_bool("DD_BOTOCORE_ADD_SPAN_POINTERS", "add_span_pointers", default=True),
    *_test_as_bool("DD_TRACE_OTEL_ENABLED", "otel_enabled", default=False),
    *_test_as_bool(
        "DD_INSTRUMENTATION_TELEMETRY_ENABLED", "telemetry_enabled", default=False
    ),
    *_test_as_bool("DD_MERGE_XRAY_TRACES", "merge_xray_traces", default=False),
    *_test_as_bool("DD_PROFILING_ENABLED", "profiling_enabled", default=False),
    *_test_as_bool("DD_LLMOBS_ENABLED", "llmobs_enabled", default=False),
    *_test_as_bool(
        "DD_EXCEPTION_REPLAY_ENABLED", "exception_replay_enabled", default=False
    ),
    *_test_as_bool(
        "DD_CAPTURE_LAMBDA_PAYLOAD", "capture_payload_enabled", default=False
    ),
    *_test_as_bool("DD_LOCAL_TEST", "local_test", default=False),
    *_test_as_bool("DD_DATA_STREAMS_ENABLED", "data_streams_enabled", default=False),
    *_test_int(
        "DD_CAPTURE_LAMBDA_PAYLOAD_MAX_DEPTH", "capture_payload_max_depth", default=10
    ),
    *_test_int(
        "DD_MIN_COLD_START_DURATION", "min_cold_start_trace_duration", default=3
    ),
    *_test_as_list(
        "DD_COLD_START_TRACE_SKIP_LIB",
        "cold_start_trace_skip_lib",
        default="ddtrace.internal.compat,ddtrace.filters",
    ),
    ("DD_SERVICE", "service", None, None),
    ("DD_SERVICE", "service", "", ""),
    ("DD_SERVICE", "service", "my_service", "my_service"),
    ("AWS_LAMBDA_FUNCTION_NAME", "aws_lambda_function_name", None, None),
    ("AWS_LAMBDA_FUNCTION_NAME", "aws_lambda_function_name", "", ""),
    (
        "AWS_LAMBDA_FUNCTION_NAME",
        "aws_lambda_function_name",
        "my_function",
        "my_function",
    ),
    ("AWS_LAMBDA_FUNCTION_NAME", "function_name", None, "function"),
    ("AWS_LAMBDA_FUNCTION_NAME", "function_name", "", ""),
    ("AWS_LAMBDA_FUNCTION_NAME", "function_name", "my_function", "my_function"),
    ("AWS_LAMBDA_FUNCTION_NAME", "is_lambda_context", None, False),
    ("AWS_LAMBDA_FUNCTION_NAME", "is_lambda_context", "", False),
    ("AWS_LAMBDA_FUNCTION_NAME", "is_lambda_context", "my_function", True),
    ("AWS_REGION", "is_gov_region", None, False),
    ("AWS_REGION", "is_gov_region", "", False),
    ("AWS_REGION", "is_gov_region", "us-gov-1", True),
    ("AWS_REGION", "is_gov_region", "us-est-1", False),
    ("DD_TRACE_EXTRACTOR", "trace_extractor", None, None),
    ("DD_TRACE_EXTRACTOR", "trace_extractor", "", ""),
    ("DD_TRACE_EXTRACTOR", "trace_extractor", "my_extractor", "my_extractor"),
    ("DD_ENV", "env", None, None),
    ("DD_ENV", "env", "", ""),
    ("DD_ENV", "env", "my_env", "my_env"),
)


@pytest.mark.parametrize("env_key,conf_key,env_val,conf_val", _test_config_from_environ)
def test_config_from_environ(env_key, conf_key, env_val, conf_val, setenv):
    setenv(env_key, env_val)
    assert getattr(config, conf_key) == conf_val


_test_config_from_environ_depends_on_tracing = (
    *_test_as_bool("DD_COLD_START_TRACING", "cold_start_tracing", default=True),
    *_test_as_bool("DD_TRACE_MANAGED_SERVICES", "make_inferred_span", default=True),
    *_test_as_bool(
        "DD_ENCODE_AUTHORIZER_CONTEXT", "encode_authorizer_context", default=True
    ),
    *_test_as_bool(
        "DD_DECODE_AUTHORIZER_CONTEXT", "decode_authorizer_context", default=True
    ),
    *_test_as_bool("DD_DATA_STREAMS_ENABLED", "data_streams_enabled", default=False),
    *_test_as_bool(
        "DD_INSTRUMENTATION_TELEMETRY_ENABLED", "telemetry_enabled", default=False
    ),
)


@pytest.mark.parametrize(
    "env_key,conf_key,env_val,conf_val", _test_config_from_environ_depends_on_tracing
)
def test_config_from_environ_depends_on_tracing(
    env_key, conf_key, env_val, conf_val, setenv
):
    setenv(env_key, env_val)
    setenv("DD_TRACE_ENABLED", "false")
    assert getattr(config, conf_key) is False


def test_config_aws_lambda_function_name(setenv):
    # these config values all access the same environment variable, test to
    # ensure the wrong value is not cached
    setenv("AWS_LAMBDA_FUNCTION_NAME", "my_function")
    assert config.aws_lambda_function_name == "my_function"
    assert config.function_name == "my_function"
    assert config.is_lambda_context is True


_test_fips_mode_from_environ = (
    (None, None, False),
    (None, "", False),
    (None, "us-gov-1", True),
    (None, "us-east-1", False),
    ("", None, False),
    ("", "", False),
    ("", "us-gov-1", False),
    ("", "us-east-1", False),
    ("true", None, True),
    ("true", "", True),
    ("true", "us-gov-1", True),
    ("true", "us-east-1", True),
    ("TRUE", None, True),
    ("TRUE", "", True),
    ("TRUE", "us-gov-1", True),
    ("TRUE", "us-east-1", True),
    ("false", None, False),
    ("false", "", False),
    ("false", "us-gov-1", False),
    ("false", "us-east-1", False),
    ("FALSE", None, False),
    ("FALSE", "", False),
    ("FALSE", "us-gov-1", False),
    ("FALSE", "us-east-1", False),
    ("1", None, False),
    ("1", "", False),
    ("1", "us-gov-1", False),
    ("1", "us-east-1", False),
    ("0", None, False),
    ("0", "", False),
    ("0", "us-gov-1", False),
    ("0", "us-east-1", False),
)


@pytest.mark.parametrize("fips_mode,region,conf_val", _test_fips_mode_from_environ)
def test_fips_mode_from_environ(fips_mode, region, conf_val, setenv):
    setenv("DD_LAMBDA_FIPS_MODE", fips_mode)
    setenv("AWS_REGION", region)
    assert config.fips_mode_enabled == conf_val


def test__get_env_does_not_log_when_env_not_set(setenv, monkeypatch):
    setenv("TEST_1", None)
    setenv("TEST_2", None)
    setenv("TEST_3", None)
    setenv("TEST_4", None)

    class Testing:
        test_1 = _get_env("TEST_1")
        test_2 = _get_env("TEST_2", "purple")
        test_3 = _get_env("TEST_3", "true", bool)
        test_4 = _get_env("TEST_4", "true", bool, depends_on_tracing=True)

    logs = []

    def cap_warn(*args, **kwargs):
        logs.append(args)

    monkeypatch.setattr("datadog_lambda.config.logger.warning", cap_warn)

    testing = Testing()
    testing.test_1
    testing.test_2
    testing.test_3
    testing.test_4

    assert not logs
