import unittest
try:
    from unittest.mock import patch, call
except ImportError:
    from mock import patch, call

from datadog_lambda.metric import (
    lambda_metric,
    _format_dd_lambda_layer_tag,
)


class TestLambdaMetric(unittest.TestCase):

    def setUp(self):
        patcher = patch('datadog_lambda.metric.lambda_stats')
        self.mock_metric_lambda_stats = patcher.start()
        self.addCleanup(patcher.stop)

    def test_lambda_metric_tagged_with_dd_lambda_layer(self):
        lambda_metric('test.metric', 1)
        lambda_metric('test.metric', 1, 123, ['tag1:test'])
        lambda_metric('test.metric', 1, tags=['tag1:test'])
        expected_tag = _format_dd_lambda_layer_tag()
        self.mock_metric_lambda_stats.distribution.assert_has_calls([
            call('test.metric', 1, tags=[expected_tag]),
            call('test.metric', 1, 123, ['tag1:test', expected_tag]),
            call('test.metric', 1, tags=['tag1:test', expected_tag]),
        ])
