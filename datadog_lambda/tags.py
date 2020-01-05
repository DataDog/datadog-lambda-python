from platform import python_version_tuple

from datadog_lambda.cold_start import get_cold_start_tag


def parse_lambda_tags_from_arn(arn):
    """Generate the list of lambda tags based on the data in the arn
    Args:
        arn (str): Lambda ARN.
            ex: arn:aws:lambda:us-east-1:123597598159:function:my-lambda[:optional-version]
    """
    # Cap the number of times to split
    split_arn = arn.split(":")

    # If ARN includes version / alias at the end, drop it
    if len(split_arn) > 7:
        split_arn = split_arn[:7]

    _, _, _, region, account_id, _, function_name = split_arn

    return [
        f"region:{region}",
        f"account_id:{account_id}",
        f"functionname:{function_name}",
    ]


def get_runtime_tag():
    """Get the runtime tag from the current Python version
    """
    major, minor, _ = python_version_tuple()

    return f"runtime:python{major}.{minor}"


def get_enhanced_metrics_tags(lambda_context):
    """Get the list of tags to apply to enhanced metrics
    """
    return parse_lambda_tags_from_arn(lambda_context.invoked_function_arn) + [
        get_cold_start_tag(),
        f"memorysize:{lambda_context.memory_limit_in_mb}",
        get_runtime_tag(),
    ]
