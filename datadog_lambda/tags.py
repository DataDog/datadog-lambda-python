import sys

from datadog_lambda import __version__
from datadog_lambda.cold_start import get_cold_start_tag


_major, _minor = sys.version_info[0], sys.version_info[1]
dd_lambda_layer_tag = f"dd_lambda_layer:datadog-python{_major}{_minor}_{__version__}"
runtime_tag = f"runtime:python{_major}.{_minor}"


def parse_lambda_tags_from_arn(lambda_context):
    """Generate the list of lambda tags based on the data in the arn
    Args:
        lambda_context: Aws lambda context object
            ex: lambda_context.arn = arn:aws:lambda:us-east-1:123597598159:function:my-lambda:1
    """
    # Set up flag for extra testing to distinguish between a version or alias
    hasAlias = False
    # Cap the number of times to spli
    split_arn = lambda_context.invoked_function_arn.split(":")

    if len(split_arn) > 7:
        hasAlias = True
        _, _, _, region, account_id, _, function_name, alias = split_arn
    else:
        _, _, _, region, account_id, _, function_name = split_arn

    # Add the standard tags to a list
    tags = [
        f"region:{region}",
        f"account_id:{account_id}",
        f"functionname:{function_name}",
    ]

    # Check if we have a version or alias
    if hasAlias:
        # If $Latest, drop the $ for datadog tag convention. A lambda alias can't start with $
        if alias.startswith("$"):
            alias = alias[1:]
        # Versions are numeric. Aliases need the executed version tag
        elif not check_if_number(alias):
            tags.append(f"executedversion:{lambda_context.function_version}")
        # create resource tag with function name and alias/version
        resource = f"resource:{function_name}:{alias}"
    else:
        # Resource is only the function name otherwise
        resource = f"resource:{function_name}"

    tags.append(resource)

    return tags


def get_library_version_tag():
    """Get datadog lambda library tag"""
    return f"datadog_lambda:v{__version__}"


def get_enhanced_metrics_tags(lambda_context):
    """Get the list of tags to apply to enhanced metrics"""
    return parse_lambda_tags_from_arn(lambda_context) + [
        get_cold_start_tag(),
        f"memorysize:{lambda_context.memory_limit_in_mb}",
        runtime_tag,
        get_library_version_tag(),
    ]


def check_if_number(alias):
    """
    Check if the alias is a version or number.
    Python 2 has no easy way to test this like Python 3
    """
    try:
        float(alias)
        return True
    except ValueError:
        return False
