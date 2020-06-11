import sys

from platform import python_version_tuple

from datadog_lambda import __version__
from datadog_lambda.cold_start import get_cold_start_tag


def _format_dd_lambda_layer_tag():
    """
    Formats the dd_lambda_layer tag, e.g., 'dd_lambda_layer:datadog-python27_1'
    """
    runtime = "python{}{}".format(sys.version_info[0], sys.version_info[1])
    return "dd_lambda_layer:datadog-{}_{}".format(runtime, __version__)


def tag_dd_lambda_layer(tags):
    """
    Used by lambda_metric to insert the dd_lambda_layer tag
    """
    dd_lambda_layer_tag = _format_dd_lambda_layer_tag()
    if tags:
        return tags + [dd_lambda_layer_tag]
    else:
        return [dd_lambda_layer_tag]


def parse_lambda_tags_from_arn(arn):
    """Generate the list of lambda tags based on the data in the arn
    Args:
        arn (str): Lambda ARN.
            ex: arn:aws:lambda:us-east-1:123597598159:function:my-lambda[:optional-version]
    """
    # Cap the number of times to split
    split_arn = arn.split(":")

    if len(split_arn) > 7:
        _, _, _, region, account_id, _, function_name, alias = split_arn
        resource = function_name + ":" + alias

    else:
        _, _, _, region, account_id, _, function_name = split_arn
        resource = function_name

    return [
        "region:{}".format(region),
        "account_id:{}".format(account_id),
        "functionname:{}".format(function_name),
        "resource:{}".format(resource),
    ]


def get_runtime_tag():
    """Get the runtime tag from the current Python version
    """
    major_version, minor_version, _ = python_version_tuple()

    return "runtime:python{major}.{minor}".format(
        major=major_version, minor=minor_version
    )


def get_enhanced_metrics_tags(lambda_context):
    """Get the list of tags to apply to enhanced metrics
    """
    return parse_lambda_tags_from_arn(lambda_context.invoked_function_arn) + [
        get_cold_start_tag(),
        "memorysize:{}".format(lambda_context.memory_limit_in_mb),
        "executedversion:{}".format(lambda_context.function_version),
        get_runtime_tag(),
        _format_dd_lambda_layer_tag(),
    ]
