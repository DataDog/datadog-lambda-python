# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.
import functools
import logging
import re

from ddtrace import tracer

logger = logging.getLogger(__name__)


def _parse_durable_execution_arn(arn):
    """
    Parses a DurableExecutionArn to extract execution name and ID.
    ARN format:
        arn:aws:lambda:{region}:{account}:function:{func}:{version}/durable-execution/{name}/{id}
    Returns (execution_name, execution_id) or None if parsing fails.
    """
    match = re.search(r"/durable-execution/([^/]+)/([^/]+)$", arn)
    if not match:
        return None
    execution_name, execution_id = match.group(1), match.group(2)
    if not execution_name or not execution_id:
        return None
    return execution_name, execution_id


def extract_durable_function_tags(event):
    """
    Extracts durable function tags from the Lambda event payload.
    Returns a dict with durable function tags, or an empty dict if the event
    is not a durable function invocation.
    """
    if not isinstance(event, dict):
        return {}

    durable_execution_arn = event.get("DurableExecutionArn")
    if not isinstance(durable_execution_arn, str):
        return {}

    parsed = _parse_durable_execution_arn(durable_execution_arn)
    if not parsed:
        logger.error("Failed to parse DurableExecutionArn: %s", durable_execution_arn)
        return {}

    execution_name, execution_id = parsed
    return {
        "durable_function_execution_name": execution_name,
        "durable_function_execution_id": execution_id,
    }


def durable_execution(func):
    """
    Decorator for AWS Lambda durable execution orchestration functions.
    Sets the durable_function_first_invocation tag on the current span
    based on whether this is the first invocation (not replaying history).
    """

    @functools.wraps(func)
    def wrapper(context, *args, **kwargs):
        try:
            is_first_invocation = not context.state.is_replaying()
            span = tracer.current_span()
            if span:
                span.set_tag(
                    "durable_function_first_invocation",
                    str(is_first_invocation).lower(),
                )
        except Exception:
            logger.debug("Failed to set durable_function_first_invocation tag")
        return func(context, *args, **kwargs)

    return wrapper
