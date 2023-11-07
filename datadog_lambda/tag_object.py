# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2021 Datadog, Inc.

from decimal import Decimal
import json
import logging

redactable_keys = ["authorization", "x-authorization", "password", "token"]
max_depth = 10
logger = logging.getLogger(__name__)


def tag_object(span, key, obj, depth=0):
    if obj is None:
        return span.set_tag(key, obj)
    if depth >= max_depth:
        return tag_object(span, key, _redact_val(key, str(obj)[0:5000]))
    depth += 1
    if _should_try_string(obj):
        parsed = None
        try:
            parsed = json.loads(obj)
            return tag_object(span, key, parsed, depth)
        except ValueError:
            redacted = _redact_val(key, obj[0:5000])
            return span.set_tag(key, redacted)
    if isinstance(obj, int) or isinstance(obj, float) or isinstance(obj, Decimal):
        return span.set_tag(key, str(obj))
    if isinstance(obj, list):
        for k, v in enumerate(obj):
            formatted_key = "{}.{}".format(key, k)
            tag_object(span, formatted_key, v, depth)
        return
    if hasattr(obj, "items"):
        for k, v in obj.items():
            formatted_key = "{}.{}".format(key, k)
            tag_object(span, formatted_key, v, depth)
        return
    if hasattr(obj, "to_dict"):
        for k, v in obj.to_dict().items():
            formatted_key = "{}.{}".format(key, k)
            tag_object(span, formatted_key, v, depth)
        return
    try:
        value_as_str = str(obj)
    except Exception:
        value_as_str = "UNKNOWN"
    return span.set_tag(key, value_as_str)


def _should_try_string(obj):
    try:
        if isinstance(obj, str) or isinstance(obj, unicode):
            return True
    except NameError:
        if isinstance(obj, bytes):
            return True

    return False


def _redact_val(k, v):
    split_key = k.split(".").pop() or k
    if split_key in redactable_keys:
        return "redacted"
    return v
