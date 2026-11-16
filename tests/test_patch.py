import pytest
import unittest
import os
import subprocess
import sys

from unittest.mock import patch, MagicMock, call

from datadog_lambda.patch import _patch_http, _ensure_patch_requests
from datadog_lambda.constants import TraceHeader

from ddtrace.contrib.internal.requests.patch import unpatch as unpatch_requests


@pytest.fixture(scope="module", autouse=True)
def reset_patches():
    unpatch_requests()


class TestPatchHTTPClients(unittest.TestCase):
    def setUp(self):
        patcher = patch("datadog_lambda.patch.get_dd_trace_context")
        self.mock_get_dd_trace_context = patcher.start()
        self.mock_get_dd_trace_context.return_value = {
            TraceHeader.TRACE_ID: "123",
            TraceHeader.PARENT_ID: "321",
            TraceHeader.SAMPLING_PRIORITY: "2",
        }
        self.addCleanup(patcher.stop)

    def test_patch_http(self):
        _patch_http()
        from http.client import HTTPSConnection

        conn = HTTPSConnection("www.datadoghq.com")
        conn.request("GET", "/")
        conn.getresponse()

        self.mock_get_dd_trace_context.assert_called()

    def test_patch_http_dict_headers(self):
        _patch_http()
        from http.client import HTTPSConnection

        headers = MagicMock(spec=dict)
        headers["fake-header"] = "fake-value"

        conn = HTTPSConnection("www.datadoghq.com")
        conn.request("GET", "/", headers=headers)
        conn.getresponse()

        self.mock_get_dd_trace_context.assert_called()
        headers.update.assert_called()

    def test_patch_http_dict_like_headers(self):
        _patch_http()
        from http.client import HTTPSConnection
        from collections.abc import MutableMapping

        headers = MagicMock(spec=MutableMapping)
        headers["fake-header"] = "fake-value"

        conn = HTTPSConnection("www.datadoghq.com")
        conn.request("GET", "/", headers=headers)
        conn.getresponse()

        self.mock_get_dd_trace_context.assert_called()
        headers.update.assert_called()

    def test_patch_requests(self):
        _ensure_patch_requests()
        import requests

        r = requests.get("https://www.datadoghq.com/")
        self.mock_get_dd_trace_context.assert_called()
        self.assertEqual(r.request.headers[TraceHeader.TRACE_ID], "123")
        self.assertEqual(r.request.headers[TraceHeader.PARENT_ID], "321")
        self.assertEqual(r.request.headers[TraceHeader.SAMPLING_PRIORITY], "2")

    def test_patch_requests_with_headers(self):
        _ensure_patch_requests()
        import requests

        r = requests.get("https://www.datadoghq.com/", headers={"key": "value"})
        self.mock_get_dd_trace_context.assert_called()
        self.assertEqual(r.request.headers["key"], "value")
        self.assertEqual(r.request.headers[TraceHeader.TRACE_ID], "123")
        self.assertEqual(r.request.headers[TraceHeader.PARENT_ID], "321")
        self.assertEqual(r.request.headers[TraceHeader.SAMPLING_PRIORITY], "2")

    def test_patch_requests_with_headers_none(self):
        _ensure_patch_requests()
        import requests

        r = requests.get("https://www.datadoghq.com/", headers=None)
        self.mock_get_dd_trace_context.assert_called()
        self.assertEqual(r.request.headers[TraceHeader.TRACE_ID], "123")
        self.assertEqual(r.request.headers[TraceHeader.PARENT_ID], "321")
        self.assertEqual(r.request.headers[TraceHeader.SAMPLING_PRIORITY], "2")


@patch("datadog_lambda.patch.patch_all_dd")
@patch("datadog_lambda.patch.config")
def test_patch_all_disables_ci_visibility_integrations(mock_config, mock_patch_all_dd):
    from datadog_lambda.patch import patch_all

    mock_config.trace_enabled = True
    mock_config.integration_test = False
    mock_config.sca_enabled = False
    patch_all()

    mock_patch_all_dd.assert_called_once_with(unittest=False, selenium=False)


@patch("datadog_lambda.config.Config.sca_enabled", True)
@patch("datadog_lambda.patch.patch_all_dd")
@patch("datadog_lambda.patch.patch_dd")
def test_sca_enabled(mock_patch_dd, mock_patch_all_dd, monkeypatch):
    from datadog_lambda.patch import patch_all

    product = MagicMock()
    monkeypatch.setitem(sys.modules, "ddtrace.internal.sca.product", product)
    monkeypatch.delenv("DD_TRACE_AWS_LAMBDA_ENABLED", raising=False)

    patch_all()

    assert product.mock_calls == [call.start(), call.post_preload()]
    mock_patch_all_dd.assert_called_once_with(
        unittest=False, selenium=False, aws_lambda=False
    )
    mock_patch_dd.assert_called_once_with(raise_errors=False, aws_lambda=True)


@pytest.mark.parametrize("failure", ["import", "start", "post_preload"])
@patch("datadog_lambda.config.Config.sca_enabled", True)
@patch("datadog_lambda.patch.patch_all_dd")
@patch("datadog_lambda.patch.patch_dd")
def test_sca_errors_caught(mock_patch_dd, mock_patch_all_dd, monkeypatch, failure):
    from datadog_lambda.patch import patch_all

    product = MagicMock()
    if failure == "import":
        product = None
    else:
        getattr(product, failure).side_effect = RuntimeError("SCA startup failed")
    monkeypatch.setitem(sys.modules, "ddtrace.internal.sca.product", product)
    monkeypatch.delenv("DD_TRACE_AWS_LAMBDA_ENABLED", raising=False)

    patch_all()

    mock_patch_dd.assert_called_once_with(raise_errors=False, aws_lambda=True)


@pytest.mark.parametrize("trace_enabled", ["true", "false"])
@pytest.mark.parametrize("lambda_enabled", ["true", "false"])
def test_sca_starts_before_handler_import(tmp_path, trace_enabled, lambda_enabled):
    (tmp_path / "startup_handler.py").write_text(
        "import os\n"
        "sca_ready_at_import = os.environ.get('SCA_READY') == 'true'\n"
        "def handler(event, context):\n"
        "    return {}\n"
    )
    code = """
import os
import sys
from types import ModuleType

product = ModuleType("ddtrace.internal.sca.product")
product.start = lambda: None
product.post_preload = lambda: os.environ.__setitem__("SCA_READY", "true")
sys.modules[product.__name__] = product

import datadog_lambda.handler as handler

assert handler.handler_module.sca_ready_at_import
expected_patch = os.environ["DD_TRACE_ENABLED"] == "true" and os.environ["DD_TRACE_AWS_LAMBDA_ENABLED"] == "true"
assert bool(getattr(handler.handler_module, "_datadog_patch", False)) == expected_patch
"""
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": os.pathsep.join([str(tmp_path), os.getcwd()]),
            "AWS_LAMBDA_FUNCTION_NAME": "sca-startup-test",
            "DD_LAMBDA_HANDLER": "startup_handler.handler",
            "DD_APPSEC_ENABLED": "false",
            "DD_APPSEC_SCA_ENABLED": "true",
            "DD_TRACE_ENABLED": trace_enabled,
            "DD_TRACE_AWS_LAMBDA_ENABLED": lambda_enabled,
        }
    )
    env.pop("SCA_READY", None)
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
