# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import os
import sys
import json
import time
import base64

import boto3
from datadog import api
from datadog.threadstats import ThreadStats
from datadog_lambda import __version__

lambda_stats = ThreadStats()
lambda_stats.start()


def _format_dd_lambda_layer_tag():
    """
    Formats the dd_lambda_layer tag, e.g., 'dd_lambda_layer:datadog-python27_1'
    """
    runtime = "python{}{}".format(sys.version_info[0], sys.version_info[1])
    return "dd_lambda_layer:datadog-{}_{}".format(runtime, __version__)


def _tag_dd_lambda_layer(tags):
    """
    Used by lambda_metric to insert the dd_lambda_layer tag
    """
    dd_lambda_layer_tag = _format_dd_lambda_layer_tag()
    if tags:
        return tags + [dd_lambda_layer_tag]
    else:
        return [dd_lambda_layer_tag]


def lambda_metric(metric_name, value, timestamp=None, tags=None):
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
    tags = _tag_dd_lambda_layer(tags)
    if os.environ.get('DD_FLUSH_TO_LOG', '').lower() == 'true':
        print(json.dumps({
            'm': metric_name,
            'v': value,
            'e': timestamp or int(time.time()),
            't': tags
        }))
    else:
        lambda_stats.distribution(
            metric_name, value, timestamp=timestamp, tags=tags
        )


# Decrypt code should run once and variables stored outside of the function
# handler so that these are decrypted once per container
DD_KMS_API_KEY = os.environ.get("DD_KMS_API_KEY")
if DD_KMS_API_KEY:
    DD_KMS_API_KEY = boto3.client("kms").decrypt(
        CiphertextBlob=base64.b64decode(DD_KMS_API_KEY)
    )["Plaintext"]

# Set API Key and Host in the module, so they only set once per container
api._api_key = os.environ.get(
    'DATADOG_API_KEY',
    os.environ.get('DD_API_KEY', DD_KMS_API_KEY),
)
api._api_host = os.environ.get(
    'DATADOG_HOST',
    'https://api.' + os.environ.get('DD_SITE', 'datadoghq.com')
)
