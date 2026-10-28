import os
import subprocess
import sys
import textwrap
import unittest
from unittest.mock import Mock, patch

from datadog_lambda import feature_flags
from datadog_lambda.config import Config


class FeatureFlagFlushTest(unittest.TestCase):
    def setUp(self):
        for name, value in [("_consecutive_timeouts", 0), ("_skip_until", 0.0)]:
            patcher = patch.object(feature_flags, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_full_budget_timeouts_back_off_and_retry_after_expiry(self):
        with patch.object(
            feature_flags, "monotonic", return_value=1000.0
        ) as now, patch.object(feature_flags, "_telemetry") as telemetry, patch.object(
            Config, "feature_flag_flush_timeout_ms", 250
        ):
            telemetry.FLUSH_API_VERSION = 1
            telemetry.flush.return_value = "timed_out"
            context = Mock(get_remaining_time_in_millis=lambda: 30000)
            for _ in range(3):
                feature_flags.flush_feature_flag_telemetry(context)
            self.assertEqual(telemetry.flush.call_count, 3)
            telemetry.flush.assert_called_with(0.25)
            for timestamp in (1000.0, 1030.0, 1059.999):
                now.return_value = timestamp
                feature_flags.flush_feature_flag_telemetry(context)
                self.assertEqual(telemetry.flush.call_count, 3)
            now.return_value = 1060.0
            telemetry.flush.return_value = "completed"
            feature_flags.flush_feature_flag_telemetry(context)
            self.assertEqual(telemetry.flush.call_count, 4)
            # Recovery starts a new streak, not an immediate second cooldown.
            telemetry.flush.return_value = "timed_out"
            for _ in range(2):
                feature_flags.flush_feature_flag_telemetry(context)
            telemetry.flush.return_value = "completed"
            feature_flags.flush_feature_flag_telemetry(context)
            self.assertEqual(telemetry.flush.call_count, 7)

    def test_completed_and_failed_flushes_reset_timeout_streak(self):
        for outcome in ("completed", "failed"):
            with self.subTest(outcome=outcome), patch.object(
                feature_flags, "_telemetry"
            ) as telemetry, patch.object(
                feature_flags, "monotonic", return_value=1000.0
            ):
                telemetry.FLUSH_API_VERSION = 1
                outcomes = [
                    "timed_out",
                    "timed_out",
                    outcome,
                    "timed_out",
                    "timed_out",
                    "completed",
                ]
                telemetry.flush.side_effect = outcomes
                for _ in outcomes:
                    feature_flags.flush_feature_flag_telemetry(
                        Mock(get_remaining_time_in_millis=lambda: 30000)
                    )
                self.assertEqual(telemetry.flush.call_count, len(outcomes))

    def test_short_budget_timeouts_neither_count_nor_reset_streak(self):
        with patch.object(feature_flags, "_telemetry") as telemetry, patch.object(
            feature_flags, "monotonic", return_value=1000.0
        ):
            telemetry.FLUSH_API_VERSION = 1
            telemetry.flush.return_value = "timed_out"
            for remaining in (30000, 200, 200, 200, 30000, 30000):
                feature_flags.flush_feature_flag_telemetry(
                    Mock(get_remaining_time_in_millis=lambda: remaining)
                )
            self.assertEqual(telemetry.flush.call_count, 6)
            feature_flags.flush_feature_flag_telemetry(
                Mock(get_remaining_time_in_millis=lambda: 30000)
            )
            self.assertEqual(telemetry.flush.call_count, 6)

    def test_budget(self):
        for remaining, cap, expected in [
            (5000, 500, 0.5),
            (200, 500, 0.1),
            (101, 500, 0.001),
        ]:
            with self.subTest(remaining=remaining), patch.object(
                feature_flags, "_telemetry"
            ) as telemetry:
                telemetry.FLUSH_API_VERSION = 1
                telemetry.flush.return_value = "completed"
                with patch.object(
                    type(feature_flags.config), "feature_flag_flush_timeout_ms", cap
                ):
                    feature_flags.flush_feature_flag_telemetry(
                        Mock(get_remaining_time_in_millis=lambda: remaining)
                    )
                telemetry.flush.assert_called_once_with(expected)

    def test_no_budget(self):
        for remaining, cap in [
            (100, 500),
            (0, 500),
            (1000, 0),
            (1000, -1),
            (1000, float("nan")),
        ]:
            with self.subTest(remaining=remaining, cap=cap), patch.object(
                feature_flags, "_telemetry"
            ) as telemetry:
                telemetry.FLUSH_API_VERSION = 1
                with patch.object(
                    type(feature_flags.config), "feature_flag_flush_timeout_ms", cap
                ):
                    feature_flags.flush_feature_flag_telemetry(
                        Mock(get_remaining_time_in_millis=lambda: remaining)
                    )
                telemetry.flush.assert_not_called()

    def test_old_tracer(self):
        for telemetry in [None, Mock(FLUSH_API_VERSION=2)]:
            with self.subTest(telemetry=telemetry), patch.object(
                feature_flags, "_telemetry", telemetry
            ):
                context = Mock()
                context.get_remaining_time_in_millis.return_value = 1000
                feature_flags.flush_feature_flag_telemetry(context)
                context.get_remaining_time_in_millis.assert_not_called()
                if telemetry is not None:
                    telemetry.flush.assert_not_called()

    def test_timeout_environment_parsing_preserves_flush(self):
        for value, expected in [
            (None, 0.5),
            ("250.5", 0.2505),
            ("", 0.5),
            ("garbage", 0.5),
            ("500ms", 0.5),
        ]:
            with self.subTest(value=value), patch.dict(os.environ), patch.object(
                feature_flags, "config", Config()
            ), patch.object(feature_flags, "_telemetry") as telemetry:
                if value is None:
                    os.environ.pop("DD_FEATURE_FLAGS_FLUSH_TIMEOUT_MS", None)
                else:
                    os.environ["DD_FEATURE_FLAGS_FLUSH_TIMEOUT_MS"] = value
                telemetry.FLUSH_API_VERSION = 1
                telemetry.flush.return_value = "completed"
                feature_flags.flush_feature_flag_telemetry(
                    Mock(get_remaining_time_in_millis=lambda: 1000)
                )
                telemetry.flush.assert_called_once_with(expected)

    def test_missing_context_and_telemetry_errors_are_safe(self):
        with patch.object(feature_flags, "_telemetry") as telemetry:
            telemetry.FLUSH_API_VERSION = 1
            telemetry.flush.side_effect = RuntimeError("unavailable")
            feature_flags.flush_feature_flag_telemetry(None)
            feature_flags.flush_feature_flag_telemetry(
                Mock(get_remaining_time_in_millis=lambda: 1000)
            )
            telemetry.flush.assert_called_once()

    def test_missing_remaining_time_skips_without_failure_log(self):
        for context in (None, object()):
            with self.subTest(context=context), patch.object(
                feature_flags, "_telemetry"
            ) as telemetry, patch.object(feature_flags, "logger") as log:
                telemetry.FLUSH_API_VERSION = 1
                feature_flags.flush_feature_flag_telemetry(context)
                telemetry.flush.assert_not_called()
                log.debug.assert_not_called()

    def test_unsupported_tracer_skip_is_logged(self):
        with patch.object(
            feature_flags, "_telemetry", Mock(FLUSH_API_VERSION=2)
        ) as telemetry, patch.object(feature_flags, "logger") as log:
            feature_flags.flush_feature_flag_telemetry(
                Mock(get_remaining_time_in_millis=lambda: 1000)
            )
            telemetry.flush.assert_not_called()
            log.debug.assert_called_once_with(
                "Skipping feature flag telemetry flush: unsupported tracer"
            )

    def test_disabled_feature_flags_do_not_import_flush_modules(self):
        code = textwrap.dedent(
            """
            import sys

            class BlockFlushImports:
                def find_spec(self, fullname, *args):
                    if fullname in (
                        "datadog_lambda.feature_flags",
                        "ddtrace.internal.openfeature._telemetry",
                    ):
                        raise AssertionError("unexpected import: " + fullname)

            sys.meta_path.insert(0, BlockFlushImports())
            from datadog_lambda import wrapper
            assert not wrapper.config.feature_flags_enabled
            assert "datadog_lambda.feature_flags" not in sys.modules
            assert "ddtrace.internal.openfeature._telemetry" not in sys.modules
            """
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            env={
                **os.environ,
                "DD_FEATURE_FLAGS_ENABLED": "false",
                "DD_INSTRUMENTATION_TELEMETRY_ENABLED": "false",
            },
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_incomplete_diagnostic(self):
        with patch.object(feature_flags, "_telemetry") as telemetry, patch.object(
            feature_flags, "logger"
        ) as log:
            telemetry.FLUSH_API_VERSION = 1
            telemetry.flush.return_value = "timed_out"
            feature_flags.flush_feature_flag_telemetry(
                Mock(get_remaining_time_in_millis=lambda: 1000)
            )
            log.debug.assert_called_with(
                "Feature flag telemetry flush incomplete: %s", "timed_out"
            )
