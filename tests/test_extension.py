import os
import sys
import unittest
import httpretty

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from datadog_lambda.extension import (
    is_extension_running,
    flush_extension,
    should_use_extension,
)


def exceptionCallback(request, uri, headers):
    raise Exception("oopsy!")


class TestLambdaExtension(unittest.TestCase):
    @patch("datadog_lambda.extension.EXTENSION_PATH", os.path.abspath(__file__))
    def test_is_extension_running_true(self):
        httpretty.enable()
        last_request = httpretty.last_request()
        httpretty.register_uri(httpretty.GET, "http://127.0.0.1:8124/lambda/hello")
        assert is_extension_running() == True
        assert httpretty.last_request() != last_request
        httpretty.disable()

    def test_is_extension_running_file_not_found(self):
        httpretty.enable()
        last_request = httpretty.last_request()
        httpretty.register_uri(httpretty.GET, "http://127.0.0.1:8124/lambda/hello")
        assert is_extension_running() == False
        assert httpretty.last_request() == last_request
        httpretty.disable()

    @patch("datadog_lambda.extension.EXTENSION_PATH", os.path.abspath(__file__))
    def test_is_extension_running_http_failure(self):
        httpretty.enable()
        last_request = httpretty.last_request()
        httpretty.register_uri(
            httpretty.GET,
            "http://127.0.0.1:8124/lambda/hello",
            status=503,
            body=exceptionCallback,
        )
        assert is_extension_running() == False
        assert httpretty.last_request() != last_request
        httpretty.disable()

    @patch("datadog_lambda.extension.EXTENSION_PATH", os.path.abspath(__file__))
    def test_flush_ok(self):
        httpretty.enable()
        last_request = httpretty.last_request()
        httpretty.register_uri(httpretty.POST, "http://127.0.0.1:8124/lambda/flush")
        assert flush_extension() == True
        assert httpretty.last_request() != last_request
        httpretty.disable()

    @patch("datadog_lambda.extension.EXTENSION_PATH", os.path.abspath(__file__))
    def test_flush_not_ok(self):
        httpretty.enable()
        last_request = httpretty.last_request()
        httpretty.register_uri(
            httpretty.POST,
            "http://127.0.0.1:8124/lambda/flush",
            status=503,
            body=exceptionCallback,
        )
        assert flush_extension() == False
        assert httpretty.last_request() != last_request
        httpretty.disable()
