# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.
import logging
import re
import ujson as json

logger = logging.getLogger(__name__)

_TRACE_CHECKPOINT_PREFIX = "_datadog_"


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
    # Use the number of operations to determine if it's the first invocation. This is
    # what the durable execution SDK does to determine the replay status.
    operations = event.get("InitialExecutionState", {}).get("Operations", [])
    is_first_invocation = len(operations) == 1
    return {
        "aws_lambda.durable_function.execution_name": execution_name,
        "aws_lambda.durable_function.execution_id": execution_id,
        "aws_lambda.durable_function.first_invocation": str(
            is_first_invocation
        ).lower(),
    }


VALID_DURABLE_STATUSES = {"SUCCEEDED", "FAILED", "PENDING"}


def _extract_context_from_durable_checkpoint(operation):
    # Checkpoint data is written by the dd-trace-py in Datadog style
    # (x-datadog-* headers). Extraction goes through the standard
    # propagator.extract path, which honors DD_TRACE_PROPAGATION_STYLE_EXTRACT.
    # The default extract list (datadog, tracecontext, baggage) already
    # includes datadog. Customers who override the extract list MUST keep
    # datadog in it.
    if not isinstance(operation, dict):
        return None

    step_details = operation.get("StepDetails")
    if not isinstance(step_details, dict):
        return None

    result = step_details.get("Result")
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except Exception:
            return None

    if not isinstance(result, dict):
        return None

    from datadog_lambda.tracing import propagator

    return propagator.extract(result)


def extract_context_from_durable_execution(event):
    operations = event.get("InitialExecutionState", {}).get("Operations")
    if isinstance(operations, dict):
        operations = list(operations.values())
    if not isinstance(operations, list) or not operations:
        return None

    highest = -1
    best_operation = None
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        name = operation.get("Name")
        if not isinstance(name, str) or not name.startswith(_TRACE_CHECKPOINT_PREFIX):
            continue
        suffix = name[len(_TRACE_CHECKPOINT_PREFIX) :]
        try:
            number = int(suffix)
        except (TypeError, ValueError):
            continue
        if number > highest:
            highest = number
            best_operation = operation

    return _extract_context_from_durable_checkpoint(best_operation)


def extract_durable_execution_status(response, event):
    if not isinstance(event, dict) or "DurableExecutionArn" not in event:
        return None
    if not isinstance(response, dict):
        return None
    status = response.get("Status")
    if status not in VALID_DURABLE_STATUSES:
        return None
    return status
