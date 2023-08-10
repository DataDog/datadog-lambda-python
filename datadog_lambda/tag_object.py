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
    if depth >= max_depth:
        return
    else:
        depth += 1

    # Check if the object has more than 450 items.
    # If it's a dictionary, then check the number of keys
    # If it's a list, then check the number of elements
    if isinstance(obj, dict) and len(obj) > 450:
        logger.warning("Payload for key %s is too large with more than 450 items. "
                       "Tagging as plain text. Please decrease your lambda payload if "
                       "you want it parsed as JSON by the backend.", key)
        return span.set_tag(key, str(obj))
    elif isinstance(obj, list) and len(obj) > 450:
        logger.warning("Payload for key %s is too large with more than 450 items. "
                       "Tagging as plain text. Please decrease your lambda payload if "
                       "you want it parsed as JSON by the backend.", key)
        return span.set_tag(key, str(obj))

    # Continue with your original logic after the above checks.
    if obj is None:
        return span.set_tag(key, obj)

    if _should_try_string(obj):
        parsed = None
        try:
            parsed = json.loads(obj)
            return tag_object(span, key, parsed, depth)
        except ValueError:
            redacted = _redact_val(key, obj[0:5000])
            return span.set_tag(key, redacted)

    if isinstance(obj, int) or isinstance(obj, float) or isinstance(obj, Decimal):
        return span.set_tag(key, obj)

    if isinstance(obj, list):
        for k, v in enumerate(obj):
            formatted_key = "{}.{}".format(key, k)
            tag_object(span, formatted_key, v, depth)
        return

    if isinstance(obj, object):
        for k in obj:
            v = obj.get(k)
            formatted_key = "{}.{}".format(key, k)
            tag_object(span, formatted_key, v, depth)
        return


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
