# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import logging

from wrapt import wrap_function_wrapper as wrap

from datadog_lambda.tracing import get_dd_trace_context

logger = logging.getLogger(__name__)

_httplib_patched = False
_requests_patched = False


def patch_all():
    """
    Patch the widely-used HTTP clients to automatically inject
    Datadog trace context.
    """
    _patch_httplib()
    _patch_requests()


def _patch_httplib():
    """
    Patch the Python `http.client` module.
    """
    global _httplib_patched
    if not _httplib_patched:
        _httplib_patched = True
        wrap(
            'http.client',
            'HTTPConnection.request',
            _wrap_httplib_request
        )
    logger.debug('Patched http.client')


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
            logger.debug('Patched requests')
        except Exception:
            logger.debug('Failed to patch requests', exc_info=True)


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
    Wrap `http.client` to inject the Datadog trace headers
    into the outgoing requests.
    """
    context = get_dd_trace_context()
    if 'headers' in kwargs:
        kwargs['headers'].update(context)
    elif len(args) >= 4:
        args[3].update(context)
    else:
        kwargs['headers'] = context
    return func(*args, **kwargs)
