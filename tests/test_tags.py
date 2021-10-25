import unittest

from unittest.mock import patch, MagicMock


from datadog_lambda.tags import parse_lambda_tags_from_arn, get_runtime_tag


def get_mock_context(
    invoked_function_arn="arn:aws:lambda:us-east-1:1234597598159:function:swf-hello-test:$Latest",
    function_version="1",
):
    lambda_context = MagicMock()
    lambda_context.invoked_function_arn = invoked_function_arn
    lambda_context.function_version = function_version
    return lambda_context


class TestMetricTags(unittest.TestCase):
    def setUp(self):
        patcher = patch("datadog_lambda.tags.python_version_tuple")
        self.mock_python_version_tuple = patcher.start()
        self.addCleanup(patcher.stop)

    def test_parse_lambda_tags_from_arn_latest(self):
        self.assertListEqual(
            parse_lambda_tags_from_arn(get_mock_context()),
            [
                "region:us-east-1",
                "account_id:1234597598159",
                "functionname:swf-hello-test",
                "resource:swf-hello-test:Latest",
            ],
        )

    def test_parse_lambda_tags_from_arn_version(self):
        lambda_context = get_mock_context()
        lambda_context.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:1234597598159:function:swf-hello-test:3"
        )
        self.assertListEqual(
            parse_lambda_tags_from_arn(lambda_context),
            [
                "region:us-east-1",
                "account_id:1234597598159",
                "functionname:swf-hello-test",
                "resource:swf-hello-test:3",
            ],
        )

    def test_parse_lambda_tags_from_arn_alias(self):
        lambda_context = get_mock_context()
        lambda_context.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:1234597598159:function:swf-hello-test:my_alias-1"
        )
        self.assertListEqual(
            parse_lambda_tags_from_arn(lambda_context),
            [
                "region:us-east-1",
                "account_id:1234597598159",
                "functionname:swf-hello-test",
                "executedversion:1",
                "resource:swf-hello-test:my_alias-1",
            ],
        )

    def test_get_runtime_tag(self):
        self.mock_python_version_tuple.return_value = ("3", "7", "2")
        self.assertEqual(get_runtime_tag(), "runtime:python3.7")
