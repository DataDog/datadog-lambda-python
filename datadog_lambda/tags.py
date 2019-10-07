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
