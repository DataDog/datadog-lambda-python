# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import logging
import os


def _get_env(key, default=None, cast=None):
    """Get an environment variable with a default value."""
    val = os.environ.get(key, default)
    if cast is not None:
        try:
            val = cast(val)
        except ValueError:
            raise ValueError(f"Invalid value for {key}: {val}")
            return cast(default)
    return val


def as_bool(val):
    """Convert a string to a boolean."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        val = val.lower()
        if val in ("true", "1", "yes"):
            return True
        elif val in ("false", "0", "no"):
            return False
    raise ValueError(f"Invalid boolean value: {val}")


class config:

    function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    flush_to_log = os.environ.get("DD_FLUSH_TO_LOG", "").lower() == "true"
    trace_enabled = os.environ.get("DD_TRACE_ENABLED", "true").lower() == "true"
    cold_start_tracing = (
        os.environ.get("DD_COLD_START_TRACING", "true").lower() == "true"
    )
    is_gov_region = os.environ.get("AWS_REGION", "").startswith("us-gov-")
    fips_mode_enabled = (
        os.environ.get(
            "DD_LAMBDA_FIPS_MODE",
            "true" if is_gov_region else "false",
        ).lower()
        == "true"
    )
    log_level = (os.environ.get("DD_LOG_LEVEL") or "INFO").upper()
    flush_in_thread = os.environ.get("DD_FLUSH_IN_THREAD", "").lower() == "true"
    enhanced_metrics_enabled = (
        os.environ.get("DD_ENHANCED_METRICS", "true").lower() == "true"
    )
    is_in_tests = os.environ.get("DD_INTEGRATION_TEST", "false").lower() == "true"
    add_span_pointers = os.environ.get(
        "DD_BOTOCORE_ADD_SPAN_POINTERS", "true"
    ).lower() in ("true", "1")
    otel_enabled = os.environ.get("DD_TRACE_OTEL_ENABLED", "false").lower() == "true"
    is_lambda_context = bool(function_name)
    telemetry_enabled = (
        os.environ.get("DD_INSTRUMENTATION_TELEMETRY_ENABLED", "false").lower()
        == "true"
    )


if config.is_gov_region or config.fips_mode_enabled:
    logger = logging.getLogger(__name__)
    logger.debug(
        "Python Lambda Layer FIPS mode is %s.",
        "enabled" if config.fips_mode_enabled else "not enabled",
    )
