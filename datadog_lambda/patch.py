# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import os
import sys
import logging
import zlib
import ujson as json

from wrapt import wrap_function_wrapper as wrap
from wrapt.importer import when_imported
from ddtrace import patch_all as patch_all_dd

from datadog_lambda.tracing import (
    get_dd_trace_context,
    dd_tracing_enabled,
)
from collections.abc import MutableMapping

logger = logging.getLogger(__name__)

_http_patched = False
_requests_patched = False
_integration_tests_patched = False


def patch_all():
    """
    Patch third-party libraries for tracing.
    """
    _patch_for_integration_tests()

    if dd_tracing_enabled:
        patch_all_dd()
    else:
        _patch_http()
        _ensure_patch_requests()


def _patch_for_integration_tests():
    """
    Patch `requests` to log the outgoing requests for integration tests.
    """
    global _integration_tests_patched
    is_in_tests = os.environ.get("DD_INTEGRATION_TEST", "false").lower() == "true"
    if not _integration_tests_patched and is_in_tests:
        wrap("requests", "Session.send", _log_request)
        _integration_tests_patched = True


def _patch_http():
    """
    Patch `http.client` (Python 3) module.
    """
    global _http_patched
    http_module = "http.client"
    if not _http_patched:
        _http_patched = True
        wrap(http_module, "HTTPConnection.request", _wrap_http_request)

    logger.debug("Patched %s", http_module)


def _ensure_patch_requests():
    """
    `requests` is third-party, may not be installed or used,
    but ensure it gets patched if installed and used.
    """
    if "requests" in sys.modules:
        # already imported, patch now
        _patch_requests(sys.modules["requests"])
    else:
        # patch when imported
        when_imported("requests")(_patch_requests)


def _patch_requests(module):
    """
    Patch the high-level HTTP client module `requests`
    if it's installed.
    """
    global _requests_patched
    if not _requests_patched:
        _requests_patched = True
        try:
            wrap("requests", "Session.request", _wrap_requests_request)
            logger.debug("Patched requests")
        except Exception:
            logger.debug("Failed to patch requests", exc_info=True)


def _wrap_requests_request(func, instance, args, kwargs):
    """
    Wrap `requests.Session.request` to inject the Datadog trace headers
    into the outgoing requests.
    """
    context = get_dd_trace_context()
    if "headers" in kwargs and isinstance(kwargs["headers"], MutableMapping):
        kwargs["headers"].update(context)
    elif len(args) >= 5 and isinstance(args[4], MutableMapping):
        args[4].update(context)
    else:
        kwargs["headers"] = context

    return func(*args, **kwargs)


def _wrap_http_request(func, instance, args, kwargs):
    """
    Wrap `http.client` (python3) to inject
    the Datadog trace headers into the outgoing requests.
    """
    context = get_dd_trace_context()
    if "headers" in kwargs and isinstance(kwargs["headers"], MutableMapping):
        kwargs["headers"].update(context)
    elif len(args) >= 4 and isinstance(args[3], MutableMapping):
        args[3].update(context)
    else:
        kwargs["headers"] = context

    return func(*args, **kwargs)


def _log_request(func, instance, args, kwargs):
    request = kwargs.get("request") or args[0]
    _print_request_string(request)
    return func(*args, **kwargs)


def _print_request_string(request):
    """Print the request so that it can be checked in integration tests

    Only used by integration tests.
    """
    method = request.method
    url = request.url

    # Sort the datapoints POSTed by their name so that snapshots always align
    data = request.body or "{}"
    # If payload is compressed, decompress it so we can parse it
    if request.headers.get("Content-Encoding") == "deflate":
        data = zlib.decompress(data)
    data_dict = json.loads(data)
    data_dict.get("series", []).sort(key=lambda series: series.get("metric"))
    sorted_data = json.dumps(data_dict)

    # Sort headers to prevent any differences in ordering
    headers = request.headers or {}
    sorted_headers = sorted(
        "{}:{}".format(key, value) for key, value in headers.items()
    )
    sorted_header_str = json.dumps(sorted_headers)
    print(
        "HTTP {} {} Headers: {} Data: {}".format(
            method, url, sorted_header_str, sorted_data
        )
    )
