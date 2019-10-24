import sys
import unittest
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from datadog_lambda.patch import (
    _patch_httplib,
    _patch_requests,
)
from datadog_lambda.constants import TraceHeader


class TestPatchHTTPClients(unittest.TestCase):

    def setUp(self):
        patcher = patch('datadog_lambda.patch.get_dd_trace_context')
        self.mock_get_dd_trace_context = patcher.start()
        self.mock_get_dd_trace_context.return_value = {
            TraceHeader.TRACE_ID: '123',
            TraceHeader.PARENT_ID: '321',
            TraceHeader.SAMPLING_PRIORITY: '2',
        }
        self.addCleanup(patcher.stop)

    def test_patch_httplib(self):
        _patch_httplib()
        if sys.version_info >= (3, 0, 0):
            import urllib.request as urllib
        else:
            import urllib2 as urllib
        urllib.urlopen("https://www.datadoghq.com/")
        self.mock_get_dd_trace_context.assert_called()

    def test_patch_requests(self):
        _patch_requests()
        import requests
        r = requests.get("https://www.datadoghq.com/")
        self.mock_get_dd_trace_context.assert_called()
        self.assertEqual(r.request.headers[TraceHeader.TRACE_ID], '123')
        self.assertEqual(r.request.headers[TraceHeader.PARENT_ID], '321')
        self.assertEqual(r.request.headers[TraceHeader.SAMPLING_PRIORITY], '2')
