import pytest

from datadog_lambda.config import config


@pytest.fixture
def setenv(monkeypatch):
    def set_env(key, value):
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)

    return set_env


_test_config_from_environ = (
    ("DD_SERVICE", "service", None, None),
    ("DD_SERVICE", "service", "", ""),
    ("DD_SERVICE", "service", "my_service", "my_service"),
    ("AWS_LAMBDA_FUNCTION_NAME", "function_name", None, "function"),
    ("AWS_LAMBDA_FUNCTION_NAME", "function_name", "", ""),
    ("AWS_LAMBDA_FUNCTION_NAME", "function_name", "my_function", "my_function"),
    ("DD_FLUSH_TO_LOG", "flush_to_log", None, False),
    ("DD_FLUSH_TO_LOG", "flush_to_log", "", False),
    ("DD_FLUSH_TO_LOG", "flush_to_log", "true", True),
    ("DD_FLUSH_TO_LOG", "flush_to_log", "TRUE", True),
    ("DD_FLUSH_TO_LOG", "flush_to_log", "false", False),
    ("DD_FLUSH_TO_LOG", "flush_to_log", "FALSE", False),
    ("DD_FLUSH_TO_LOG", "flush_to_log", "1", True),  # CHANGED
    ("DD_FLUSH_TO_LOG", "flush_to_log", "0", False),
    ("DD_FLUSH_TO_LOG", "flush_to_log", "purple", False),
    ("DD_LOGS_INJECTION", "logs_injection", None, True),
    ("DD_LOGS_INJECTION", "logs_injection", "", False),
    ("DD_LOGS_INJECTION", "logs_injection", "true", True),
    ("DD_LOGS_INJECTION", "logs_injection", "TRUE", True),
    ("DD_LOGS_INJECTION", "logs_injection", "false", False),
    ("DD_LOGS_INJECTION", "logs_injection", "FALSE", False),
    ("DD_LOGS_INJECTION", "logs_injection", "1", True),  # CHANGED
    ("DD_LOGS_INJECTION", "logs_injection", "0", False),
    ("DD_LOGS_INJECTION", "logs_injection", "purple", False),
    ("DD_TRACE_ENABLED", "trace_enabled", None, True),
    ("DD_TRACE_ENABLED", "trace_enabled", "", False),
    ("DD_TRACE_ENABLED", "trace_enabled", "true", True),
    ("DD_TRACE_ENABLED", "trace_enabled", "TRUE", True),
    ("DD_TRACE_ENABLED", "trace_enabled", "false", False),
    ("DD_TRACE_ENABLED", "trace_enabled", "FALSE", False),
    ("DD_TRACE_ENABLED", "trace_enabled", "1", True),  # CHANGED
    ("DD_TRACE_ENABLED", "trace_enabled", "0", False),
    ("DD_TRACE_ENABLED", "trace_enabled", "purple", False),
    ("DD_COLD_START_TRACING", "cold_start_tracing", None, True),
    ("DD_COLD_START_TRACING", "cold_start_tracing", "", False),
    ("DD_COLD_START_TRACING", "cold_start_tracing", "true", True),
    ("DD_COLD_START_TRACING", "cold_start_tracing", "TRUE", True),
    ("DD_COLD_START_TRACING", "cold_start_tracing", "false", False),
    ("DD_COLD_START_TRACING", "cold_start_tracing", "FALSE", False),
    ("DD_COLD_START_TRACING", "cold_start_tracing", "1", True),  # CHANGED
    ("DD_COLD_START_TRACING", "cold_start_tracing", "0", False),
    ("DD_COLD_START_TRACING", "cold_start_tracing", "purple", False),
    ("AWS_REGION", "is_gov_region", None, False),
    ("AWS_REGION", "is_gov_region", "", False),
    ("AWS_REGION", "is_gov_region", "us-gov-1", True),
    ("AWS_REGION", "is_gov_region", "us-est-1", False),
    ("DD_FLUSH_IN_THREAD", "flush_in_thread", None, False),
    ("DD_FLUSH_IN_THREAD", "flush_in_thread", "", False),
    ("DD_FLUSH_IN_THREAD", "flush_in_thread", "true", True),
    ("DD_FLUSH_IN_THREAD", "flush_in_thread", "TRUE", True),
    ("DD_FLUSH_IN_THREAD", "flush_in_thread", "false", False),
    ("DD_FLUSH_IN_THREAD", "flush_in_thread", "FALSE", False),
    ("DD_FLUSH_IN_THREAD", "flush_in_thread", "1", True),  # CHANGED
    ("DD_FLUSH_IN_THREAD", "flush_in_thread", "0", False),
    ("DD_FLUSH_IN_THREAD", "flush_in_thread", "purple", False),
    ("DD_ENHANCED_METRICS", "enhanced_metrics_enabled", None, True),
    ("DD_ENHANCED_METRICS", "enhanced_metrics_enabled", "", False),
    ("DD_ENHANCED_METRICS", "enhanced_metrics_enabled", "true", True),
    ("DD_ENHANCED_METRICS", "enhanced_metrics_enabled", "TRUE", True),
    ("DD_ENHANCED_METRICS", "enhanced_metrics_enabled", "false", False),
    ("DD_ENHANCED_METRICS", "enhanced_metrics_enabled", "FALSE", False),
    ("DD_ENHANCED_METRICS", "enhanced_metrics_enabled", "1", True),  # CHANGED
    ("DD_ENHANCED_METRICS", "enhanced_metrics_enabled", "0", False),
    ("DD_ENHANCED_METRICS", "enhanced_metrics_enabled", "purple", False),
    ("DD_INTEGRATION_TEST", "is_in_tests", None, False),
    ("DD_INTEGRATION_TEST", "is_in_tests", "", False),
    ("DD_INTEGRATION_TEST", "is_in_tests", "true", True),
    ("DD_INTEGRATION_TEST", "is_in_tests", "TRUE", True),
    ("DD_INTEGRATION_TEST", "is_in_tests", "false", False),
    ("DD_INTEGRATION_TEST", "is_in_tests", "FALSE", False),
    ("DD_INTEGRATION_TEST", "is_in_tests", "1", True),  # CHANGED
    ("DD_INTEGRATION_TEST", "is_in_tests", "0", False),
    ("DD_INTEGRATION_TEST", "is_in_tests", "purple", False),
    ("DD_BOTOCORE_ADD_SPAN_POINTERS", "add_span_pointers", None, True),
    ("DD_BOTOCORE_ADD_SPAN_POINTERS", "add_span_pointers", "", False),
    ("DD_BOTOCORE_ADD_SPAN_POINTERS", "add_span_pointers", "true", True),
    ("DD_BOTOCORE_ADD_SPAN_POINTERS", "add_span_pointers", "TRUE", True),
    ("DD_BOTOCORE_ADD_SPAN_POINTERS", "add_span_pointers", "false", False),
    ("DD_BOTOCORE_ADD_SPAN_POINTERS", "add_span_pointers", "FALSE", False),
    ("DD_BOTOCORE_ADD_SPAN_POINTERS", "add_span_pointers", "1", True),
    ("DD_BOTOCORE_ADD_SPAN_POINTERS", "add_span_pointers", "0", False),
    ("DD_BOTOCORE_ADD_SPAN_POINTERS", "add_span_pointers", "purple", False),
    ("DD_TRACE_OTEL_ENABLED", "otel_enabled", None, False),
    ("DD_TRACE_OTEL_ENABLED", "otel_enabled", "", False),
    ("DD_TRACE_OTEL_ENABLED", "otel_enabled", "true", True),
    ("DD_TRACE_OTEL_ENABLED", "otel_enabled", "TRUE", True),
    ("DD_TRACE_OTEL_ENABLED", "otel_enabled", "false", False),
    ("DD_TRACE_OTEL_ENABLED", "otel_enabled", "FALSE", False),
    ("DD_TRACE_OTEL_ENABLED", "otel_enabled", "1", True),  # CHANGED
    ("DD_TRACE_OTEL_ENABLED", "otel_enabled", "0", False),
    ("DD_TRACE_OTEL_ENABLED", "otel_enabled", "purple", False),
    ("AWS_LAMBDA_FUNCTION_NAME", "is_lambda_context", None, False),
    ("AWS_LAMBDA_FUNCTION_NAME", "is_lambda_context", "", False),
    ("AWS_LAMBDA_FUNCTION_NAME", "is_lambda_context", "my_function", True),
    ("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "telemetry_enabled", None, False),
    ("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "telemetry_enabled", "", False),
    ("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "telemetry_enabled", "true", True),
    ("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "telemetry_enabled", "TRUE", True),
    ("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "telemetry_enabled", "false", False),
    ("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "telemetry_enabled", "FALSE", False),
    ("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "telemetry_enabled", "1", True),  # CHANGED
    ("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "telemetry_enabled", "0", False),
    ("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "telemetry_enabled", "purple", False),
    ("DD_MERGE_XRAY_TRACES", "merge_xray_traces", None, False),
    ("DD_MERGE_XRAY_TRACES", "merge_xray_traces", "", False),
    ("DD_MERGE_XRAY_TRACES", "merge_xray_traces", "true", True),
    ("DD_MERGE_XRAY_TRACES", "merge_xray_traces", "TRUE", True),
    ("DD_MERGE_XRAY_TRACES", "merge_xray_traces", "false", False),
    ("DD_MERGE_XRAY_TRACES", "merge_xray_traces", "FALSE", False),
    ("DD_MERGE_XRAY_TRACES", "merge_xray_traces", "1", True),  # CHANGED
    ("DD_MERGE_XRAY_TRACES", "merge_xray_traces", "0", False),
    ("DD_MERGE_XRAY_TRACES", "merge_xray_traces", "purple", False),
    ("DD_TRACE_EXTRACTOR", "trace_extractor", None, None),
    ("DD_TRACE_EXTRACTOR", "trace_extractor", "", ""),
    ("DD_TRACE_EXTRACTOR", "trace_extractor", "my_extractor", "my_extractor"),
    ("DD_CAPTURE_PAYLOAD_MAX_DEPTH", "capture_payload_max_depth", None, 10),
    ("DD_CAPTURE_PAYLOAD_MAX_DEPTH", "capture_payload_max_depth", "", 10),
    ("DD_CAPTURE_PAYLOAD_MAX_DEPTH", "capture_payload_max_depth", "5", 5),
    ("DD_CAPTURE_PAYLOAD_MAX_DEPTH", "capture_payload_max_depth", "0", 0),
    ("DD_CAPTURE_PAYLOAD_MAX_DEPTH", "capture_payload_max_depth", "2.5", 10),
    ("DD_CAPTURE_PAYLOAD_MAX_DEPTH", "capture_payload_max_depth", "-1", -1),
    ("DD_CAPTURE_PAYLOAD_MAX_DEPTH", "capture_payload_max_depth", "purple", 10),
    ("DD_PROFILING_ENABLED", "profiling_enabled", None, False),
    ("DD_PROFILING_ENABLED", "profiling_enabled", "", False),
    ("DD_PROFILING_ENABLED", "profiling_enabled", "true", True),
    ("DD_PROFILING_ENABLED", "profiling_enabled", "TRUE", True),
    ("DD_PROFILING_ENABLED", "profiling_enabled", "false", False),
    ("DD_PROFILING_ENABLED", "profiling_enabled", "FALSE", False),
    ("DD_PROFILING_ENABLED", "profiling_enabled", "1", True),  # CHANGED
    ("DD_PROFILING_ENABLED", "profiling_enabled", "0", False),
    ("DD_PROFILING_ENABLED", "profiling_enabled", "purple", False),
    ("DD_LLMOBS_ENABLED", "llmobs_enabled", None, False),
    ("DD_LLMOBS_ENABLED", "llmobs_enabled", "", False),
    ("DD_LLMOBS_ENABLED", "llmobs_enabled", "true", True),
    ("DD_LLMOBS_ENABLED", "llmobs_enabled", "TRUE", True),
    ("DD_LLMOBS_ENABLED", "llmobs_enabled", "false", False),
    ("DD_LLMOBS_ENABLED", "llmobs_enabled", "FALSE", False),
    ("DD_LLMOBS_ENABLED", "llmobs_enabled", "1", True),  # CHANGED
    ("DD_LLMOBS_ENABLED", "llmobs_enabled", "0", False),
    ("DD_LLMOBS_ENABLED", "llmobs_enabled", "purple", False),
    ("DD_EXCEPTION_REPLAY_ENABLED", "exception_replay_enabled", None, False),
    ("DD_EXCEPTION_REPLAY_ENABLED", "exception_replay_enabled", "", False),
    ("DD_EXCEPTION_REPLAY_ENABLED", "exception_replay_enabled", "true", True),
    ("DD_EXCEPTION_REPLAY_ENABLED", "exception_replay_enabled", "TRUE", True),
    ("DD_EXCEPTION_REPLAY_ENABLED", "exception_replay_enabled", "false", False),
    ("DD_EXCEPTION_REPLAY_ENABLED", "exception_replay_enabled", "FALSE", False),
    ("DD_EXCEPTION_REPLAY_ENABLED", "exception_replay_enabled", "1", True),  # CHANGED
    ("DD_EXCEPTION_REPLAY_ENABLED", "exception_replay_enabled", "0", False),
    ("DD_EXCEPTION_REPLAY_ENABLED", "exception_replay_enabled", "purple", False),
    ("DD_ENV", "env", None, None),
    ("DD_ENV", "env", "", ""),
    ("DD_ENV", "env", "my_env", "my_env"),
)


@pytest.mark.parametrize("env_key,conf_key,env_val,conf_val", _test_config_from_environ)
def test_config_from_environ(env_key, conf_key, env_val, conf_val, setenv):
    setenv(env_key, env_val)
    assert getattr(config, conf_key) == conf_val


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
