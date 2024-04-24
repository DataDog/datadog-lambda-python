import os
import sys
import unittest
from unittest.mock import patch

from tests.utils import get_mock_context


class TestHandler(unittest.TestCase):
    def tearDown(self):
        for mod in sys.modules.copy():
            if mod.startswith("datadog_lambda.handler"):
                del sys.modules[mod]

    def test_dd_lambda_handler_env_var_none(self):
        with self.assertRaises(Exception) as context:
            import datadog_lambda.handler as handler

            assert context.exception == handler.HandlerError(
                "DD_LAMBDA_HANDLER is not defined. Can't use prebuilt datadog handler"
            )

    @patch.dict(os.environ, {"DD_LAMBDA_HANDLER": "malformed"}, clear=True)
    def test_dd_lambda_handler_env_var_malformed(self):
        with self.assertRaises(Exception) as context:
            import datadog_lambda.handler as handler

            assert context.exception == handler.HandlerError(
                "Value malformed for DD_LAMBDA_HANDLER has invalid format."
            )

    @patch.dict(os.environ, {"DD_LAMBDA_HANDLER": "nonsense.nonsense"}, clear=True)
    @patch("datadog_lambda.wrapper.emit_telemetry_on_exception_outside_of_handler")
    @patch("time.time_ns", return_value=42)
    def test_exception_importing_module(self, mock_time, mock_emit_telemetry):
        with self.assertRaises(ModuleNotFoundError) as test_context:
            import datadog_lambda.handler

            lambda_context = get_mock_context()
            datadog_lambda.handler.handler.__call__(None, lambda_context)
        mock_emit_telemetry.assert_called_once_with(
            lambda_context, test_context.exception, "nonsense", 0
        )

    @patch.dict(os.environ, {"DD_LAMBDA_HANDLER": "nonsense.nonsense"}, clear=True)
    @patch("importlib.import_module", return_value=None)
    @patch("datadog_lambda.wrapper.emit_telemetry_on_exception_outside_of_handler")
    @patch("time.time_ns", return_value=42)
    def test_exception_getting_handler_func(
        self, mock_time, mock_emit_telemetry, mock_import
    ):
        with self.assertRaises(AttributeError) as test_context:
            import datadog_lambda.handler

            lambda_context = get_mock_context()
            datadog_lambda.handler.handler.__call__(None, lambda_context)
        mock_emit_telemetry.assert_called_once_with(
            lambda_context, test_context.exception, "nonsense", 0
        )

    @patch.dict(os.environ, {"DD_LAMBDA_HANDLER": "nonsense.nonsense"}, clear=True)
    @patch("importlib.import_module")
    @patch("datadog_lambda.wrapper.emit_telemetry_on_exception_outside_of_handler")
    @patch("datadog_lambda.wrapper.datadog_lambda_wrapper")
    def test_handler_success(
        self, mock_lambda_wrapper, mock_emit_telemetry, mock_import
    ):
        def nonsense():
            pass

        mock_import.nonsense.return_value = nonsense

        import datadog_lambda.handler

        lambda_context = get_mock_context()
        datadog_lambda.handler.handler.__call__(None, lambda_context)

        mock_emit_telemetry.assert_not_called()
        mock_lambda_wrapper.assert_called_once_with(mock_import().nonsense)
