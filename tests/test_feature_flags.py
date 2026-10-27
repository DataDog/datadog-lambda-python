import importlib.util
import os
import unittest
from unittest.mock import Mock, patch

from datadog_lambda import feature_flags
from datadog_lambda import wrapper
from datadog_lambda.config import Config


class FeatureFlagFlushTest(unittest.TestCase):
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

    def test_wrapper_preserves_result_and_exception_when_cleanup_fails(self):
        for raises in [False, True]:
            original = ValueError("handler error")
            handler = (
                Mock(side_effect=original)
                if raises
                else Mock(return_value={"ok": True})
            )
            # Isolate invocation control flow from tracing/metrics initialization.
            decorated = object.__new__(wrapper._LambdaDecorator)
            decorated.func = handler
            decorated.blocking_response = None
            decorated.span = None
            decorated._before = Mock()
            decorated._after = Mock(side_effect=RuntimeError("cleanup error"))
            context = Mock(get_remaining_time_in_millis=lambda: 30000)
            with patch.object(wrapper, "flush_feature_flag_telemetry") as flush, patch(
                "datadog_lambda.metric.submit_errors_metric",
                side_effect=RuntimeError("metrics error"),
            ):
                if raises:
                    with self.assertRaises(ValueError) as caught:
                        decorated({}, context)
                    self.assertIs(caught.exception, original)
                else:
                    self.assertEqual(decorated({}, context), {"ok": True})
                flush.assert_called_once_with(context)


class FeatureFlagTracerIntegrationTest(unittest.TestCase):
    @unittest.skipUnless(
        feature_flags._telemetry is not None
        and importlib.util.find_spec("openfeature") is not None,
        "requires tracer flush contract v1 and the optional OpenFeature SDK",
    )
    def test_short_warm_invocations_flush_both_writers(self):
        from ddtrace.internal.openfeature._flagevaluation_writer import (
            FlagEvaluationWriter,
            _EvalEvent,
        )
        from ddtrace.internal.openfeature._evp_transport import EVPRoute
        from ddtrace.internal.openfeature.writer import ExposureWriter

        route = EVPRoute("http://agent:8126", "/evp_proxy/v2", {})
        selector = Mock(configuration_source="agentless")
        selector.select.return_value = route
        selector.send.side_effect = lambda route, send: send(route)
        connection = Mock()
        connection.getresponse.return_value.status = 202
        evaluations = FlagEvaluationWriter(
            route_selector=selector, connection_factory=lambda *a, **k: connection
        )
        exposures = ExposureWriter(
            enabled=True,
            route_selector=selector,
            connection_factory=lambda *a, **k: connection,
        )
        original = ValueError("handler failure")

        def handler(event, context):
            evaluations.enqueue(
                _EvalEvent("flag", "on", "allocation", "subject", {}, False, "", 1)
            )
            exposures.enqueue({"timestamp": 1})
            if event.get("raise"):
                raise original
            return {"ok": True}

        decorated = object.__new__(wrapper._LambdaDecorator)
        decorated.func = handler
        decorated.blocking_response = None
        decorated.span = None
        decorated._before = Mock()
        decorated._after = Mock(side_effect=RuntimeError("unrelated cleanup"))
        context = Mock(get_remaining_time_in_millis=lambda: 30000)
        with patch("datadog_lambda.metric.submit_errors_metric"):
            self.assertEqual(decorated({}, context), {"ok": True})
            self.assertEqual(connection.request.call_count, 2)
            with self.assertRaises(ValueError) as caught:
                decorated({"raise": True}, context)
            self.assertIs(caught.exception, original)
            self.assertEqual(connection.request.call_count, 4)
            self.assertEqual(decorated({}, context), {"ok": True})
            self.assertEqual(connection.request.call_count, 6)
