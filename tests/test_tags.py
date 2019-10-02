import unittest

from datadog_lambda.tags import parse_lambda_tags_from_arn, get_tags_from_context
from tests.test_wrapper import get_mock_context


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

    def test_get_tags_from_context(self):
        cold_start_request_id = "first-request-id"
        self.assertListEqual(
            get_tags_from_context(
                get_mock_context(aws_request_id=cold_start_request_id),
                cold_start_request_id,
            ),
            [
                "region:us-west-1",
                "account_id:123457598159",
                "functionname:python-layer-test",
                "memorysize:256",
                "cold_start:true",
            ],
        )

        self.assertListEqual(
            get_tags_from_context(
                get_mock_context(aws_request_id="non-cold-start-request-id"),
                cold_start_request_id,
            ),
            [
                "region:us-west-1",
                "account_id:123457598159",
                "functionname:python-layer-test",
                "memorysize:256",
                "cold_start:false",
            ],
        )

