# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import os
import time
import logging
import ujson as json
from datetime import datetime, timedelta

from datadog_lambda.extension import should_use_extension
from datadog_lambda.tags import get_enhanced_metrics_tags, dd_lambda_layer_tag

logger = logging.getLogger(__name__)

lambda_stats = None
extension_thread_stats = None

flush_in_thread = os.environ.get("DD_FLUSH_IN_THREAD", "").lower() == "true"

if should_use_extension:
    from datadog_lambda.statsd_writer import StatsDWriter

    lambda_stats = StatsDWriter()
else:
    # Periodical flushing in a background thread is NOT guaranteed to succeed
    # and leads to data loss. When disabled, metrics are only flushed at the
    # end of invocation. To make metrics submitted from a long-running Lambda
    # function available sooner, consider using the Datadog Lambda extension.
    from datadog_lambda.thread_stats_writer import ThreadStatsWriter
    from datadog_lambda.api import init_api

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
    flush_to_logs = os.environ.get("DD_FLUSH_TO_LOG", "").lower() == "true"
    tags = [] if tags is None else list(tags)
    tags.append(dd_lambda_layer_tag)

    if should_use_extension and timestamp is not None:
        # The extension does not support timestamps for distributions so we create a
        # a thread stats writer to submit metrics with timestamps to the API
        timestamp_ceiling = int(
            (datetime.now() - timedelta(hours=4)).timestamp()
        )  # 4 hours ago
        if isinstance(timestamp, datetime):
            timestamp = int(timestamp.timestamp())
        if timestamp_ceiling > timestamp:
            logger.warning(
                "Timestamp %s is older than 4 hours, not submitting metric %s",
                timestamp,
                metric_name,
            )
            return
        global extension_thread_stats
        if extension_thread_stats is None:
            from datadog_lambda.thread_stats_writer import ThreadStatsWriter
            from datadog_lambda.api import init_api

            init_api()
            extension_thread_stats = ThreadStatsWriter(flush_in_thread)

        extension_thread_stats.distribution(
            metric_name, value, tags=tags, timestamp=timestamp
        )
        return

    if should_use_extension:
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


def write_metric_point_to_stdout(metric_name, value, timestamp=None, tags=[]):
    """Writes the specified metric point to standard output"""
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

    if extension_thread_stats is not None:
        if lambda_context is not None:
            tags = get_enhanced_metrics_tags(lambda_context)
            split_arn = lambda_context.invoked_function_arn.split(":")
            if len(split_arn) > 7:
                # Get rid of the alias
                split_arn.pop()
            arn = ":".join(split_arn)
            tags.append("function_arn:" + arn)
        extension_thread_stats.flush(tags)


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
