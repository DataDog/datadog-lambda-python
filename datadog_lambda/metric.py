import os
import sys

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


def _tag_dd_lambda_layer(args, kwargs):
    """
    Used by lambda_metric to insert the dd_lambda_layer tag
    """
    dd_lambda_layer_tag = _format_dd_lambda_layer_tag()
    if 'tags' in kwargs:
        kwargs['tags'].append(dd_lambda_layer_tag)
    elif len(args) >= 4:
        args[3].append(dd_lambda_layer_tag)
    else:
        kwargs['tags'] = [dd_lambda_layer_tag]


def lambda_metric(*args, **kwargs):
    """
    Submit a data point to Datadog distribution metrics.
    https://docs.datadoghq.com/graphing/metrics/distributions/
    """
    _tag_dd_lambda_layer(args, kwargs)
    lambda_stats.distribution(*args, **kwargs)


def init_api_client():
    """
    No-op GET to initialize the requests connection with DD's endpoints,
    to make the final flush faster.

    We keep alive the Requests session, this means that we can re-use
    the connection. The consequence is that the HTTP Handshake, which
    can take hundreds of ms, is now made at the beginning of a lambda
    instead of at the end.

    By making the initial request async, we spare a lot of execution
    time in the lambdas.
    """
    api._api_key = os.environ.get('DATADOG_API_KEY')
    api._api_host = os.environ.get('DATADOG_HOST', 'https://api.datadoghq.com')
    try:
        api.api_client.APIClient.submit('GET', 'validate')
    except Exception:
        pass
