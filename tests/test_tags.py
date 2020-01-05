import unittest
from unittest.mock import patch

from datadog_lambda.tags import parse_lambda_tags_from_arn, get_runtime_tag


class TestMetricTags(unittest.TestCase):
    def setUp(self):
        patcher = patch("datadog_lambda.tags.python_version_tuple")
        self.mock_python_version_tuple = patcher.start()
        self.addCleanup(patcher.stop)

    def test_parse_lambda_tags_from_arn(self):
        self.assertListEqual(
            parse_lambda_tags_from_arn(
                "arn:aws:lambda:us-east-1:1234597598159:function:swf-hello-test"
            ),
            [
                "region:us-east-1",
                "account_id:1234597598159",
                "functionname:swf-hello-test",
            ],
        )

        self.assertListEqual(
            parse_lambda_tags_from_arn(
                "arn:aws:lambda:us-west-1:1234597598159:function:other-function:function-alias"
            ),
            [
                "region:us-west-1",
                "account_id:1234597598159",
                "functionname:other-function",
            ],
        )

    def test_get_runtime_tag(self):
        self.mock_python_version_tuple.return_value = ("3", "7", "2")
        self.assertEqual(get_runtime_tag(), "runtime:python3.7")
