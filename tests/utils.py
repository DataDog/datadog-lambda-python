from unittest.mock import MagicMock

function_arn = "arn:aws:lambda:us-west-1:123457598159:function:python-layer-test"


class ClientContext(object):
    def __init__(self, custom=None):
        self.custom = custom


def get_mock_context(
    aws_request_id="request-id-1",
    memory_limit_in_mb="256",
    invoked_function_arn=function_arn,
    function_version="1",
    function_name="Function",
    custom=None,
):
    lambda_context = MagicMock()
    lambda_context.aws_request_id = aws_request_id
    lambda_context.memory_limit_in_mb = memory_limit_in_mb
    lambda_context.invoked_function_arn = invoked_function_arn
    lambda_context.function_version = function_version
    lambda_context.function_name = function_name
    lambda_context.client_context = ClientContext(custom)
    return lambda_context
