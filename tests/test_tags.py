import unittest

from unittest.mock import patch

from datadog_lambda.tags import parse_lambda_tags_from_arn

from tests.utils import get_mock_context


class TestMetricTags(unittest.TestCase):
    def setUp(self):
        patcher = patch("sys.version_info", (3, 12, 0))
        self.mock_python_version_tuple = patcher.start()
        self.addCleanup(patcher.stop)

    def test_parse_lambda_tags_from_arn_latest(self):
        lambda_context = get_mock_context()
        lambda_context.invoked_function_arn = (
            "arn:aws:lambda:us-east-1:1234597598159:function:swf-hello-test:$Latest"
        )
        self.assertListEqual(
            parse_lambda_tags_from_arn(lambda_context),
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
