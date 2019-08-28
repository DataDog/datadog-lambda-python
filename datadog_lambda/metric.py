# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

import os
import sys
import json
import time
import logging

from datadog.threadstats import ThreadStats
from datadog_lambda import __version__
from datadog import api
from datadog_lambda.config import get_config

logger = logging.getLogger(__name__)

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
    if os.environ.get("DD_FLUSH_TO_LOG", "").lower() == "true":
        logger.debug("Sending metric %s to Datadog via log forwarder", metric_name)
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
    else:
        logger.debug("Sending metric %s to Datadog via lambda layer", metric_name)
        lambda_stats.distribution(metric_name, value, timestamp=timestamp, tags=tags)


api_key, api_host = get_config()
api._api_key = api_key
api._api_host = "https://api." + api_host
