# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import os
import json
import time
import base64
import logging

from botocore.exceptions import ClientError
import boto3
from datadog import api, initialize, statsd
from datadog.threadstats import ThreadStats
from datadog_lambda.extension import should_use_extension
from datadog_lambda.tags import get_enhanced_metrics_tags, tag_dd_lambda_layer

KMS_ENCRYPTION_CONTEXT_KEY = "LambdaFunctionName"
ENHANCED_METRICS_NAMESPACE_PREFIX = "aws.lambda.enhanced"

logger = logging.getLogger(__name__)


class StatsWriter:
    def distribution(self, metric_name, value, tags=[], timestamp=None):
        raise NotImplementedError()

    def flush(self):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()


class StatsDWriter(StatsWriter):
    """
    Writes distribution metrics using StatsD protocol
    """

    def __init__(self):
        options = {"statsd_host": "127.0.0.1", "statsd_port": 8125}
        initialize(**options)

    def distribution(self, metric_name, value, tags=[], timestamp=None):
        statsd.distribution(metric_name, value, tags=tags)

    def flush(self):
        pass

    def stop(self):
        pass


class ThreadStatsWriter(StatsWriter):
    """
    Writes distribution metrics using the ThreadStats class
    """

    def __init__(self, flush_in_thread):
        self.thread_stats = ThreadStats(compress_payload=True)
        self.thread_stats.start(flush_in_thread=flush_in_thread)

    def distribution(self, metric_name, value, tags=[], timestamp=None):
        self.thread_stats.distribution(
            metric_name, value, tags=tags, timestamp=timestamp
        )

    def flush(self):
        """ "Flush distributions from ThreadStats to Datadog.
        Modified based on `datadog.threadstats.base.ThreadStats.flush()`,
        to gain better control over exception handling.
        """
        _, dists = self.thread_stats._get_aggregate_metrics_and_dists(float("inf"))
        count_dists = len(dists)
        if not count_dists:
            logger.debug("No distributions to flush. Continuing.")

        self.thread_stats.flush_count += 1
        logger.debug(
            "Flush #%s sending %s distributions",
            self.thread_stats.flush_count,
            count_dists,
        )
        try:
            self.thread_stats.reporter.flush_distributions(dists)
        except Exception as e:
            # The nature of the root issue https://bugs.python.org/issue41345 is complex,
            # but comprehensive tests suggest that it is safe to retry on this specific error.
            if isinstance(
                e, api.exceptions.ClientError
            ) and "RemoteDisconnected" in str(e):
                logger.debug(
                    "Retry flush #%s due to RemoteDisconnected",
                    self.thread_stats.flush_count,
                )
                try:
                    self.thread_stats.reporter.flush_distributions(dists)
                except Exception:
                    logger.debug(
                        "Flush #%s failed after retry",
                        self.thread_stats.flush_count,
                        exc_info=True,
                    )
            else:
                logger.debug(
                    "Flush #%s failed", self.thread_stats.flush_count, exc_info=True
                )

    def stop(self):
        self.thread_stats.stop()


lambda_stats = None
if should_use_extension:
    lambda_stats = StatsDWriter()
else:
    # Periodical flushing in a background thread is NOT guaranteed to succeed
    # and leads to data loss. When disabled, metrics are only flushed at the
    # end of invocation. To make metrics submitted from a long-running Lambda
    # function available sooner, consider using the Datadog Lambda extension.
    flush_in_thread = os.environ.get("DD_FLUSH_IN_THREAD", "").lower() == "true"
    lambda_stats = ThreadStatsWriter(flush_in_thread)


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
            }
        )
    )


def flush_stats():
    lambda_stats.flush()


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


def decrypt_kms_api_key(kms_client, ciphertext):
    """
    Decodes and deciphers the base64-encoded ciphertext given as a parameter using KMS.
    For this to work properly, the Lambda function must have the appropriate IAM permissions.

    Args:
        kms_client: The KMS client to use for decryption
        ciphertext (string): The base64-encoded ciphertext to decrypt
    """
    decoded_bytes = base64.b64decode(ciphertext)

    """
    The Lambda console UI changed the way it encrypts environment variables. The current behavior
    as of May 2021 is to encrypt environment variables using the function name as an encryption
    context. Previously, the behavior was to encrypt environment variables without an encryption
    context. We need to try both, as supplying the incorrect encryption context will cause
    decryption to fail.
    """
    # Try with encryption context
    function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    try:
        plaintext = kms_client.decrypt(
            CiphertextBlob=decoded_bytes,
            EncryptionContext={
                KMS_ENCRYPTION_CONTEXT_KEY: function_name,
            },
        )["Plaintext"].decode("utf-8")
    except ClientError:
        logger.debug(
            "Failed to decrypt ciphertext with encryption context, retrying without"
        )
        # Try without encryption context
        plaintext = kms_client.decrypt(CiphertextBlob=decoded_bytes)[
            "Plaintext"
        ].decode("utf-8")

    return plaintext


# Set API Key
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
        kms_client = boto3.client("kms")
        api._api_key = decrypt_kms_api_key(kms_client, DD_KMS_API_KEY)
    else:
        api._api_key = DD_API_KEY

logger.debug("Setting DATADOG_API_KEY of length %d", len(api._api_key))

# Set DATADOG_HOST, to send data to a non-default Datadog datacenter
api._api_host = os.environ.get(
    "DATADOG_HOST", "https://api." + os.environ.get("DD_SITE", "datadoghq.com")
)
logger.debug("Setting DATADOG_HOST to %s", api._api_host)

# Unmute exceptions from datadog api client, so we can catch and handle them
api._mute = False
