# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import logging
import os

logger = logging.getLogger(__name__)


def _get_env(key, default=None, cast=None, depends_on_tracing=False):
    @property
    def _getter(self):
        if not hasattr(self, prop_key):
            val = self._resolve_env(key, default, cast, depends_on_tracing)
            setattr(self, prop_key, val)
        return getattr(self, prop_key)

    prop_key = f"_config_{key}"
    return _getter


def as_bool(val):
    return val.lower() == "true" or val == "1"


def as_list(val):
    return [val.strip() for val in val.split(",") if val.strip()]


class Config:
    def _resolve_env(self, key, default=None, cast=None, depends_on_tracing=False):
        if depends_on_tracing and not self.trace_enabled:
            return False
        val = os.environ.get(key, default)
        if cast is not None:
            try:
                val = cast(val)
            except (ValueError, TypeError):
                msg = (
                    "Failed to cast environment variable '%s' with "
                    "value '%s' to type %s. Using default value '%s'."
                )
                logger.warning(msg, key, val, cast.__name__, default)
                val = default
        return val

    service = _get_env("DD_SERVICE")
    env = _get_env("DD_ENV")

    cold_start_tracing = _get_env(
        "DD_COLD_START_TRACING", "true", as_bool, depends_on_tracing=True
    )
    min_cold_start_trace_duration = _get_env("DD_MIN_COLD_START_DURATION", 3, int)
    cold_start_trace_skip_lib = _get_env(
        "DD_COLD_START_TRACE_SKIP_LIB",
        "ddtrace.internal.compat,ddtrace.filters",
        as_list,
    )

    capture_payload_max_depth = _get_env("DD_CAPTURE_LAMBDA_PAYLOAD_MAX_DEPTH", 10, int)
    capture_payload_enabled = _get_env("DD_CAPTURE_LAMBDA_PAYLOAD", "false", as_bool)

    trace_enabled = _get_env("DD_TRACE_ENABLED", "true", as_bool)
    make_inferred_span = _get_env(
        "DD_TRACE_MANAGED_SERVICES", "true", as_bool, depends_on_tracing=True
    )
    encode_authorizer_context = _get_env(
        "DD_ENCODE_AUTHORIZER_CONTEXT", "true", as_bool, depends_on_tracing=True
    )
    decode_authorizer_context = _get_env(
        "DD_DECODE_AUTHORIZER_CONTEXT", "true", as_bool, depends_on_tracing=True
    )
    add_span_pointers = _get_env("DD_BOTOCORE_ADD_SPAN_POINTERS", "true", as_bool)
    trace_extractor = _get_env("DD_TRACE_EXTRACTOR")

    enhanced_metrics_enabled = _get_env("DD_ENHANCED_METRICS", "true", as_bool)

    flush_in_thread = _get_env("DD_FLUSH_IN_THREAD", "false", as_bool)
    flush_to_log = _get_env("DD_FLUSH_TO_LOG", "false", as_bool)
    logs_injection = _get_env("DD_LOGS_INJECTION", "true", as_bool)
    merge_xray_traces = _get_env("DD_MERGE_XRAY_TRACES", "false", as_bool)

    otel_enabled = _get_env("DD_TRACE_OTEL_ENABLED", "false", as_bool)
    profiling_enabled = _get_env("DD_PROFILING_ENABLED", "false", as_bool)
    llmobs_enabled = _get_env("DD_LLMOBS_ENABLED", "false", as_bool)
    exception_replay_enabled = _get_env("DD_EXCEPTION_REPLAY_ENABLED", "false", as_bool)
    data_streams_enabled = _get_env(
        "DD_DATA_STREAMS_ENABLED", "false", as_bool, depends_on_tracing=True
    )
    appsec_enabled = _get_env("DD_APPSEC_ENABLED", "false", as_bool)
    sca_enabled = _get_env("DD_APPSEC_SCA_ENABLED", "false", as_bool)

    is_gov_region = _get_env("AWS_REGION", "", lambda x: x.startswith("us-gov-"))

    local_test = _get_env("DD_LOCAL_TEST", "false", as_bool)
    integration_test = _get_env("DD_INTEGRATION_TEST", "false", as_bool)

    aws_lambda_function_name = _get_env("AWS_LAMBDA_FUNCTION_NAME")

    @property
    def function_name(self):
        if not hasattr(self, "_config_function_name"):
            if self.aws_lambda_function_name is None:
                self._config_function_name = "function"
            else:
                self._config_function_name = self.aws_lambda_function_name
        return self._config_function_name

    @property
    def is_lambda_context(self):
        if not hasattr(self, "_config_is_lambda_context"):
            self._config_is_lambda_context = bool(self.aws_lambda_function_name)
        return self._config_is_lambda_context

    @property
    def fips_mode_enabled(self):
        if not hasattr(self, "_config_fips_mode_enabled"):
            self._config_fips_mode_enabled = (
                os.environ.get(
                    "DD_LAMBDA_FIPS_MODE",
                    "true" if self.is_gov_region else "false",
                ).lower()
                == "true"
            )
        return self._config_fips_mode_enabled

    def _reset(self):
        for attr in dir(self):
            if attr.startswith("_config_"):
                delattr(self, attr)


config = Config()

if config.is_gov_region or config.fips_mode_enabled:
    logger.debug(
        "Python Lambda Layer FIPS mode is %s.",
        "enabled" if config.fips_mode_enabled else "not enabled",
    )


if (
    "DD_INSTRUMENTATION_TELEMETRY_ENABLED" not in os.environ
    and not config.sca_enabled
    and not config.appsec_enabled
):
    os.environ["DD_INSTRUMENTATION_TELEMETRY_ENABLED"] = "false"
