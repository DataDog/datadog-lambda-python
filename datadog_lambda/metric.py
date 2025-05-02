# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import logging
import os
import time
from datetime import datetime, timedelta

import ujson as json

from datadog_lambda.extension import should_use_extension
from datadog_lambda.tags import dd_lambda_layer_tag, get_enhanced_metrics_tags

logger = logging.getLogger(__name__)

lambda_stats = None

flush_in_thread = os.environ.get("DD_FLUSH_IN_THREAD", "").lower() == "true"

if should_use_extension:
    from datadog_lambda.statsd_writer import StatsDWriter

    lambda_stats = StatsDWriter()
else:
    # Periodical flushing in a background thread is NOT guaranteed to succeed
    # and leads to data loss. When disabled, metrics are only flushed at the
    # end of invocation. To make metrics submitted from a long-running Lambda
    # function available sooner, consider using the Datadog Lambda extension.
    from datadog_lambda.api import init_api
    from datadog_lambda.thread_stats_writer import ThreadStatsWriter

    init_api()
    lambda_stats = ThreadStatsWriter(flush_in_thread)

enhanced_metrics_enabled = (
    os.environ.get("DD_ENHANCED_METRICS", "true").lower() == "true"
)


def lambda_metric(metric_name, value, timestamp=None, tags=None, force_async=False):
    """
    Submit a data point to Datadog distribution metrics.
    https://docs.datadoghq.com/graphing/metrics/distributions/

    When DD_FLUSH_TO_LOG is True, write metric to log, and
    wait for the Datadog Log Forwarder Lambda function to submit
    the metrics asynchronously.

    Otherwise, the metrics will be submitted to the Datadog API
    periodically and at the end of the function execution in a
    background thread.

    Note that if the extension is present, it will override the DD_FLUSH_TO_LOG value
    and always use the layer to send metrics to the extension
    """
    if not metric_name or not isinstance(metric_name, str):
        logger.warning(
            "Ignoring metric submission. Invalid metric name: %s", metric_name
        )
        return

    try:
        float(value)
    except (ValueError, TypeError):
        logger.warning(
            "Ignoring metric submission for metric '%s' because the value is not numeric: %r",
            metric_name,
            value,
        )
        return

    flush_to_logs = os.environ.get("DD_FLUSH_TO_LOG", "").lower() == "true"
    tags = [] if tags is None else list(tags)
    tags.append(dd_lambda_layer_tag)

    if should_use_extension:
        if timestamp is not None:
            if isinstance(timestamp, datetime):
                timestamp = int(timestamp.timestamp())

            timestamp_floor = int((datetime.now() - timedelta(hours=4)).timestamp())
            if timestamp < timestamp_floor:
                logger.warning(
                    "Timestamp %s is older than 4 hours, not submitting metric %s",
                    timestamp,
                    metric_name,
                )
                return

        logger.debug(
            "Sending metric %s value %s to Datadog via extension", metric_name, value
        )
        lambda_stats.distribution(metric_name, value, tags=tags, timestamp=timestamp)

    else:
        if flush_to_logs or force_async:
            write_metric_point_to_stdout(
                metric_name, value, timestamp=timestamp, tags=tags
            )
        else:
            lambda_stats.distribution(
                metric_name, value, tags=tags, timestamp=timestamp
            )


def write_metric_point_to_stdout(metric_name, value, timestamp=None, tags=None):
    """Writes the specified metric point to standard output"""
    tags = tags or []

    logger.debug(
        "Sending metric %s value %s to Datadog via log forwarder", metric_name, value
    )
    print(
        json.dumps(
            {
                "m": metric_name,
                "v": value,
                "e": timestamp or int(time.time()),
                "t": tags,
            },
            escape_forward_slashes=False,
        )
    )


def flush_stats(lambda_context=None):
    lambda_stats.flush()


def submit_enhanced_metric(metric_name, lambda_context):
    """Submits the enhanced metric with the given name

    Args:
        metric_name (str): metric name w/o enhanced prefix i.e. "invocations" or "errors"
        lambda_context (object): Lambda context dict passed to the function by AWS
    """
    if not enhanced_metrics_enabled:
        logger.debug(
            "Not submitting enhanced metric %s because enhanced metrics are disabled",
            metric_name,
        )
        return
    tags = get_enhanced_metrics_tags(lambda_context)
    metric_name = "aws.lambda.enhanced." + metric_name
    # Enhanced metrics always use an async submission method, (eg logs or extension).
    lambda_metric(metric_name, 1, timestamp=None, tags=tags, force_async=True)


def submit_invocations_metric(lambda_context):
    """Increment aws.lambda.enhanced.invocations by 1, applying runtime, layer, and cold_start tags

    Args:
        lambda_context (object): Lambda context dict passed to the function by AWS
    """
    submit_enhanced_metric("invocations", lambda_context)


def submit_errors_metric(lambda_context):
    """Increment aws.lambda.enhanced.errors by 1, applying runtime, layer, and cold_start tags

    Args:
        lambda_context (object): Lambda context dict passed to the function by AWS
    """
    submit_enhanced_metric("errors", lambda_context)


def submit_dynamodb_stream_type_metric(event):
    stream_view_type = (
        event.get("Records", [{}])[0].get("dynamodb", {}).get("StreamViewType")
    )
    if stream_view_type:
        lambda_metric(
            "datadog.serverless.dynamodb.stream.type",
            1,
            timestamp=None,
            tags=[f"streamtype:{stream_view_type}"],
            force_async=True,
        )
