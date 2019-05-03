# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import sys

from wrapt import wrap_function_wrapper as wrap

from datadog_lambda.tracing import get_dd_trace_context

if sys.version_info >= (3, 0, 0):
    httplib_module = 'http.client'
else:
    httplib_module = 'httplib'

_httplib_patched = False
_requests_patched = False
_botocore_requests_patched = False


def patch_all():
    """
    Patch the widely-used HTTP clients to automatically inject
    Datadog trace context.
    """
    _patch_httplib()
    _patch_requests()
    _patch_botocore_requests()


def _patch_httplib():
    """
    Patch the Python built-in `httplib` (Python 2) or
    `http.client` (Python 3) module.
    """
    global _httplib_patched
    if not _httplib_patched:
        _httplib_patched = True
        wrap(
            httplib_module,
            'HTTPConnection.request',
            _wrap_httplib_request
        )


def _patch_requests():
    """
    Patch the high-level HTTP client module `requests`
    if it's installed.
    """
    global _requests_patched
    if not _requests_patched:
        _requests_patched = True
        try:
            wrap(
                'requests',
                'Session.request',
                _wrap_requests_request
            )
        except ImportError:
            pass


def _patch_botocore_requests():
    """
    Patch the `requests` module that is packaged into `botocore`.
    https://stackoverflow.com/questions/40741282/cannot-use-requests-module-on-aws-lambda
    """
    global _botocore_requests_patched
    if not _botocore_requests_patched:
        _botocore_requests_patched = True
        try:
            wrap(
                'botocore.vendored.requests',
                'Session.request',
                _wrap_requests_request
            )
        except ImportError:
            pass


def _wrap_requests_request(func, instance, args, kwargs):
    """
    Wrap `requests.Session.request` to inject the Datadog trace headers
    into the outgoing requests.
    """
    context = get_dd_trace_context()
    if 'headers' in kwargs:
        kwargs['headers'].update(context)
    elif len(args) >= 5:
        args[4].update(context)
    else:
        kwargs['headers'] = context
    return func(*args, **kwargs)


def _wrap_httplib_request(func, instance, args, kwargs):
    """
    Wrap `httplib` (python2) or `http.client` (python3) to inject
    the Datadog trace headers into the outgoing requests.
    """
    context = get_dd_trace_context()
    if 'headers' in kwargs:
        kwargs['headers'].update(context)
    elif len(args) >= 4:
        args[3].update(context)
    else:
        kwargs['headers'] = context
    return func(*args, **kwargs)
