import os
import unittest
try:
    from unittest.mock import patch, call, ANY
except ImportError:
    from mock import patch, call, ANY

from datadog_lambda.wrapper import datadog_lambda_wrapper
from datadog_lambda.metric import lambda_metric


class TestDatadogLambdaWrapper(unittest.TestCase):

    def setUp(self):
        patcher = patch('datadog_lambda.metric.lambda_stats')
        self.mock_metric_lambda_stats = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch('datadog_lambda.wrapper.lambda_stats')
        self.mock_wrapper_lambda_stats = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch('datadog_lambda.wrapper.extract_dd_trace_context')
        self.mock_extract_dd_trace_context = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch('datadog_lambda.wrapper.patch_all')
        self.mock_patch_all = patcher.start()
        self.addCleanup(patcher.stop)

    def test_datadog_lambda_wrapper(self):
        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}
        lambda_context = {}
        lambda_handler(lambda_event, lambda_context)

        self.mock_metric_lambda_stats.distribution.assert_has_calls([
            call('test.metric', 100, timestamp=None, tags=ANY)
        ])
        self.mock_wrapper_lambda_stats.flush.assert_called()
        self.mock_extract_dd_trace_context.assert_called_with(lambda_event)
        self.mock_patch_all.assert_called()

    def test_datadog_lambda_wrapper_flush_to_log(self):
        os.environ["DD_FLUSH_TO_LOG"] = 'True'

        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}
        lambda_context = {}
        lambda_handler(lambda_event, lambda_context)

        self.mock_metric_lambda_stats.distribution.assert_not_called()
        self.mock_wrapper_lambda_stats.flush.assert_not_called()
        self.mock_extract_dd_trace_context.assert_called_with(lambda_event)
        self.mock_patch_all.assert_called()

        del os.environ["DD_FLUSH_TO_LOG"]
