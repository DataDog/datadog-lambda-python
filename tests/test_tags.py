import unittest

from datadog_lambda.tags import parse_lambda_tags_from_arn


class TestMetricTags(unittest.TestCase):
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

