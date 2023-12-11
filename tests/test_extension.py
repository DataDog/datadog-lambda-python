import http.server
import os
import threading
import unittest

from unittest.mock import patch

from datadog_lambda.extension import (
    is_extension_running,
    flush_extension,
    should_use_extension,
)


class MockServer(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.raises = False
        self.called = False

        class handler(http.server.BaseHTTPRequestHandler):
            def do_POST(sf):
                self.called = True
                sf.send_response(500 if self.raises else 200)
                sf.end_headers()

            do_GET = do_POST

        self.server = http.server.HTTPServer(("127.0.0.1", 8124), handler)

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.join(timeout=0)


class TestLambdaExtension(unittest.TestCase):
    def setUp(self):
        self.server = MockServer()
        self.server.start()

    def tearDown(self):
        self.server.stop()

    @patch("datadog_lambda.extension.EXTENSION_PATH", os.path.abspath(__file__))
    def test_is_extension_running_true(self):
        assert is_extension_running()
        assert self.server.called

    def test_is_extension_running_file_not_found(self):
        assert not is_extension_running()
        assert not self.server.called

    @patch("datadog_lambda.extension.EXTENSION_PATH", os.path.abspath(__file__))
    def test_is_extension_running_http_failure(self):
        self.server.raises = True
        assert not is_extension_running()
        assert self.server.called

    @patch("datadog_lambda.extension.EXTENSION_PATH", os.path.abspath(__file__))
    def test_flush_ok(self):
        assert flush_extension()
        assert self.server.called

    @patch("datadog_lambda.extension.EXTENSION_PATH", os.path.abspath(__file__))
    def test_flush_not_ok(self):
        self.server.raises = True
        assert not flush_extension()
        assert self.server.called
