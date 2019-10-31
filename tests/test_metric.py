import os
import unittest

try:
    from unittest.mock import patch, call
except ImportError:
    from mock import patch, call

from datadog_lambda.metric import lambda_metric, _format_dd_lambda_layer_tag


class TestLambdaMetric(unittest.TestCase):
    def setUp(self):
        patcher = patch("datadog_lambda.metric.lambda_stats")
        self.mock_metric_lambda_stats = patcher.start()
        self.addCleanup(patcher.stop)

    def test_lambda_metric_tagged_with_dd_lambda_layer(self):
        lambda_metric("test", 1)
        lambda_metric("test", 1, 123, [])
        lambda_metric("test", 1, tags=["tag1:test"])
        expected_tag = _format_dd_lambda_layer_tag()
        self.mock_metric_lambda_stats.distribution.assert_has_calls(
            [
                call("test", 1, timestamp=None, tags=[expected_tag]),
                call("test", 1, timestamp=123, tags=[expected_tag]),
                call("test", 1, timestamp=None, tags=["tag1:test", expected_tag]),
            ]
        )

    def test_lambda_metric_flush_to_log(self):
        os.environ["DD_FLUSH_TO_LOG"] = "True"

        lambda_metric("test", 1)
        self.mock_metric_lambda_stats.distribution.assert_not_called()

        del os.environ["DD_FLUSH_TO_LOG"]
