# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import os
import json
import time
import base64
import logging

import boto3
from datadog import api, initialize, statsd
from datadog.threadstats import ThreadStats
from datadog_lambda.extension import should_use_extension
from datadog_lambda.tags import get_enhanced_metrics_tags, tag_dd_lambda_layer


ENHANCED_METRICS_NAMESPACE_PREFIX = "aws.lambda.enhanced"

logger = logging.getLogger(__name__)


class StatsDWrapper:
    """
    Wraps StatsD calls, to give an identical interface to ThreadStats
    """

    def __init__(self):
        options = {"statsd_host": "127.0.0.1", "statsd_port": 8125}
        initialize(**options)

    def distribution(self, metric_name, value, tags=[], timestamp=None):
        statsd.distribution(metric_name, value, tags=tags)

    def flush(self, value):
        pass


lambda_stats = None
if should_use_extension:
    lambda_stats = StatsDWrapper()
else:
    lambda_stats = ThreadStats(compress_payload=True)
    lambda_stats.start()


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
    """
    flush_to_logs = os.environ.get("DD_FLUSH_TO_LOG", "").lower() == "true"
    tags = tag_dd_lambda_layer(tags)

    if flush_to_logs or (force_async and not should_use_extension):
        write_metric_point_to_stdout(metric_name, value, timestamp=timestamp, tags=tags)
    else:
        logger.debug("Sending metric %s to Datadog via lambda layer", metric_name)
        lambda_stats.distribution(metric_name, value, tags=tags, timestamp=timestamp)


def write_metric_point_to_stdout(metric_name, value, timestamp=None, tags=[]):
    """Writes the specified metric point to standard output
    """
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
            }
        )
    )


def are_enhanced_metrics_enabled():
    """Check env var to find if enhanced metrics should be submitted

    Returns:
        boolean for whether enhanced metrics are enabled
    """
    # DD_ENHANCED_METRICS defaults to true
    return os.environ.get("DD_ENHANCED_METRICS", "true").lower() == "true"


def submit_enhanced_metric(metric_name, lambda_context):
    """Submits the enhanced metric with the given name

    Args:
        metric_name (str): metric name w/o enhanced prefix i.e. "invocations" or "errors"
        lambda_context (dict): Lambda context dict passed to the function by AWS
    """
    if not are_enhanced_metrics_enabled():
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
        lambda_context (dict): Lambda context dict passed to the function by AWS
    """
    submit_enhanced_metric("invocations", lambda_context)


def submit_errors_metric(lambda_context):
    """Increment aws.lambda.enhanced.errors by 1, applying runtime, layer, and cold_start tags

    Args:
        lambda_context (dict): Lambda context dict passed to the function by AWS
    """
    submit_enhanced_metric("errors", lambda_context)


# Set API Key and Host in the module, so they only set once per container
if not api._api_key:
    DD_API_KEY_SECRET_ARN = os.environ.get("DD_API_KEY_SECRET_ARN", "")
    DD_API_KEY_SSM_NAME = os.environ.get("DD_API_KEY_SSM_NAME", "")
    DD_KMS_API_KEY = os.environ.get("DD_KMS_API_KEY", "")
    DD_API_KEY = os.environ.get("DD_API_KEY", os.environ.get("DATADOG_API_KEY", ""))
    if DD_API_KEY_SECRET_ARN:
        api._api_key = boto3.client("secretsmanager").get_secret_value(
            SecretId=DD_API_KEY_SECRET_ARN
        )["SecretString"]
    elif DD_API_KEY_SSM_NAME:
        api._api_key = boto3.client("ssm").get_parameter(
            Name=DD_API_KEY_SSM_NAME, WithDecryption=True
        )["Parameter"]["Value"]
    elif DD_KMS_API_KEY:
        api._api_key = boto3.client("kms").decrypt(
            CiphertextBlob=base64.b64decode(DD_KMS_API_KEY)
        )["Plaintext"]
    else:
        api._api_key = DD_API_KEY
logger.debug("Setting DATADOG_API_KEY of length %d", len(api._api_key))

# Set DATADOG_HOST, to send data to a non-default Datadog datacenter
api._api_host = os.environ.get(
    "DATADOG_HOST", "https://api." + os.environ.get("DD_SITE", "datadoghq.com")
)
logger.debug("Setting DATADOG_HOST to %s", api._api_host)
