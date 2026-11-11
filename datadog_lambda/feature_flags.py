"""Compatibility boundary for invocation-end feature flag telemetry."""

import logging
import math
from time import monotonic

from datadog_lambda.config import config

try:
    from ddtrace.internal.openfeature import _telemetry
except ImportError:
    _telemetry = None


logger = logging.getLogger(__name__)
SAFETY_MARGIN_MS = 100.0
MAX_CONSECUTIVE_TIMEOUTS = 3
TIMEOUT_BACKOFF_S = 60.0
# Warm invocations share this state; a new process starts with no cooldown.
_consecutive_timeouts = 0
_skip_until = 0.0


def flush_feature_flag_telemetry(context):
    global _consecutive_timeouts, _skip_until
    try:
        if _telemetry is None:
            return
        if getattr(_telemetry, "FLUSH_API_VERSION", None) != 1:
            logger.debug("Skipping feature flag telemetry flush: unsupported tracer")
            return
        cap_ms = config.feature_flag_flush_timeout_ms
        if not math.isfinite(cap_ms) or cap_ms <= 0:
            return
        # No remaining-time information means no safe invocation budget.
        get_remaining_ms = getattr(context, "get_remaining_time_in_millis", None)
        if get_remaining_ms is None:
            return
        budget_ms = min(cap_ms, get_remaining_ms() - SAFETY_MARGIN_MS)
        if budget_ms <= 0:
            logger.debug(
                "Skipping feature flag telemetry flush: no invocation time remains"
            )
            return
        if monotonic() < _skip_until:
            logger.debug("Skipping feature flag telemetry flush: backing off")
            return
        outcome = _telemetry.flush(budget_ms / 1000.0)
        if outcome != "timed_out":
            _consecutive_timeouts = 0
        elif budget_ms >= cap_ms:
            # A short invocation budget says nothing about intake health.
            _consecutive_timeouts += 1
            if _consecutive_timeouts >= MAX_CONSECUTIVE_TIMEOUTS:
                _consecutive_timeouts = 0
                _skip_until = monotonic() + TIMEOUT_BACKOFF_S
        if outcome != "completed":
            logger.debug("Feature flag telemetry flush incomplete: %s", outcome)
    except Exception:
        # Never replace the response or the original handler exception.
        logger.debug("Feature flag telemetry flush failed", exc_info=True)
