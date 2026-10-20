"""Compatibility boundary for invocation-end feature flag telemetry."""

import logging
import math

from datadog_lambda.config import config

try:
    from ddtrace.internal.openfeature import _telemetry
except ImportError:
    _telemetry = None


logger = logging.getLogger(__name__)
SAFETY_MARGIN_MS = 100.0


def flush_feature_flag_telemetry(context):
    try:
        if _telemetry is None or getattr(_telemetry, "FLUSH_API_VERSION", None) != 1:
            return
        cap_ms = config.feature_flag_flush_timeout_ms
        if not math.isfinite(cap_ms) or cap_ms <= 0:
            return
        # No remaining-time information means no safe invocation budget.
        remaining_ms = context.get_remaining_time_in_millis()
        budget_ms = min(cap_ms, remaining_ms - SAFETY_MARGIN_MS)
        if budget_ms <= 0:
            logger.debug(
                "Skipping feature flag telemetry flush: no invocation time remains"
            )
            return
        outcome = _telemetry.flush(budget_ms / 1000.0)
        if outcome != "completed":
            logger.debug("Feature flag telemetry flush incomplete: %s", outcome)
    except Exception:
        # Never replace the response or the original handler exception.
        logger.debug("Feature flag telemetry flush failed", exc_info=True)
