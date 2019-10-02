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
        "region:{}".format(region),
        "account_id:{}".format(account_id),
        "functionname:{}".format(function_name),
    ]


def get_tags_from_context(context, cold_start_request_id):
    """Uses properties of the Lambda context to create the list of tags

    Args:
        context (dict<str, multiple types>): context this Lambda was invoked with
        cold_start_request_id (str): the first request ID to execute in this container

    Returns:
        tag list (str[]): list of string tags in key:value format
    """
    tags = parse_lambda_tags_from_arn(context.invoked_function_arn)
    tags.append("memorysize:{}".format(context.memory_limit_in_mb))

    did_request_cold_start = cold_start_request_id == context.aws_request_id
    cold_start_tag = "cold_start:{}".format(str(did_request_cold_start).lower())
    tags.append(cold_start_tag)

    return tags
