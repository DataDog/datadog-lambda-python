# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import logging
import os

logger = logging.getLogger(__name__)


def _get_env(key, default=None, cast=None):
    @property
    def _getter(self):
        if not hasattr(self, prop_key):
            val = os.environ.get(key, default)
            if cast is not None:
                try:
                    val = cast(val)
                except (ValueError, TypeError):
                    logger.warning(
                        "Failed to cast environment variable '%s' with value '%s' to type %s. Using default value '%s'.",
                        key,
                        val,
                        cast.__name__,
                        default,
                    )
                    val = default
            setattr(self, prop_key, val)
        return getattr(self, prop_key)

    prop_key = f"_config_{key}"
    return _getter


def as_bool(val):
    return val.lower() == "true" or val == "1"


class Config:

    service = _get_env("DD_SERVICE")
    add_span_pointers = _get_env("DD_BOTOCORE_ADD_SPAN_POINTERS", "true", as_bool)
    cold_start_tracing = _get_env("DD_COLD_START_TRACING", "true", as_bool)
    enhanced_metrics_enabled = _get_env("DD_ENHANCED_METRICS", "true", as_bool)
    flush_in_thread = _get_env("DD_FLUSH_IN_THREAD", "false", as_bool)
    flush_to_log = _get_env("DD_FLUSH_TO_LOG", "false", as_bool)
    logs_injection = _get_env("DD_LOGS_INJECTION", "true", as_bool)
    function_name = _get_env("AWS_LAMBDA_FUNCTION_NAME", "function")
    is_gov_region = _get_env("AWS_REGION", "", lambda x: x.startswith("us-gov-"))
    is_in_tests = _get_env("DD_INTEGRATION_TEST", "false", as_bool)
    is_lambda_context = _get_env("AWS_LAMBDA_FUNCTION_NAME", None, bool)
    otel_enabled = _get_env("DD_TRACE_OTEL_ENABLED", "false", as_bool)
    telemetry_enabled = _get_env(
        "DD_INSTRUMENTATION_TELEMETRY_ENABLED", "false", as_bool
    )
    trace_enabled = _get_env("DD_TRACE_ENABLED", "true", as_bool)
    merge_xray_traces = _get_env("DD_MERGE_XRAY_TRACES", "false", as_bool)
    trace_extractor = _get_env("DD_TRACE_EXTRACTOR")
    capture_payload_max_depth = _get_env("DD_CAPTURE_PAYLOAD_MAX_DEPTH", 10, int)
    profiling_enabled = _get_env("DD_PROFILING_ENABLED", "false", as_bool)
    llmobs_enabled = _get_env("DD_LLMOBS_ENABLED", "false", as_bool)

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
