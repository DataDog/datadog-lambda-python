import sys
import unittest

try:
    from unittest.mock import patch, MagicMock
except ImportError:
    from mock import patch, MagicMock

from datadog_lambda.patch import _patch_httplib, _ensure_patch_requests
from datadog_lambda.constants import TraceHeader


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

    def test_patch_httplib(self):
        _patch_httplib()
        from http.client import HTTPSConnection
        

        conn = HTTPSConnection("www.datadoghq.com")
        conn.request("GET", "/")
        conn.getresponse()

        self.mock_get_dd_trace_context.assert_called()

    def test_patch_httplib_dict_headers(self):
        _patch_httplib()
        
        from http.client import HTTPSConnection
    
        headers = MagicMock(spec=dict)
        headers["fake-header"] = "fake-value"

        conn = HTTPSConnection("www.datadoghq.com")
        conn.request("GET", "/", headers=headers)
        conn.getresponse()

        self.mock_get_dd_trace_context.assert_called()
        headers.update.assert_called()

    def test_patch_httplib_dict_like_headers(self):
        _patch_httplib()
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
