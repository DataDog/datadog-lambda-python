import base64
import json
import os
import unittest

from unittest.mock import patch, call, ANY, MagicMock
from datadog_lambda.constants import TraceHeader

from datadog_lambda.wrapper import datadog_lambda_wrapper
from datadog_lambda.metric import lambda_metric
from datadog_lambda.thread_stats_writer import ThreadStatsWriter


def get_mock_context(
    aws_request_id="request-id-1",
    memory_limit_in_mb="256",
    invoked_function_arn="arn:aws:lambda:us-west-1:123457598159:function:python-layer-test:1",
    function_version="1",
    client_context={},
):
    lambda_context = MagicMock()
    lambda_context.aws_request_id = aws_request_id
    lambda_context.memory_limit_in_mb = memory_limit_in_mb
    lambda_context.invoked_function_arn = invoked_function_arn
    lambda_context.function_version = function_version
    lambda_context.client_context = client_context
    return lambda_context


class TestDatadogLambdaWrapper(unittest.TestCase):
    def setUp(self):
        # Force @datadog_lambda_wrapper to always create a real
        # (not no-op) wrapper.
        datadog_lambda_wrapper._force_wrap = True

        patcher = patch(
            "datadog.threadstats.reporters.HttpReporter.flush_distributions"
        )
        self.mock_threadstats_flush_distributions = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.wrapper.extract_dd_trace_context")
        self.mock_extract_dd_trace_context = patcher.start()
        self.mock_extract_dd_trace_context.return_value = ({}, None, None)
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.wrapper.set_correlation_ids")
        self.mock_set_correlation_ids = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.wrapper.inject_correlation_ids")
        self.mock_inject_correlation_ids = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.wrapper.patch_all")
        self.mock_patch_all = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.cold_start.is_cold_start")
        self.mock_is_cold_start = patcher.start()
        self.mock_is_cold_start.return_value = True
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.tags.python_version_tuple")
        self.mock_python_version_tuple = patcher.start()
        self.mock_python_version_tuple.return_value = ("3", "9", "10")
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.metric.write_metric_point_to_stdout")
        self.mock_write_metric_point_to_stdout = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.tags.get_library_version_tag")
        self.mock_format_dd_lambda_layer_tag = patcher.start()
        # Mock the layer version so we don't have to update tests on every version bump
        self.mock_format_dd_lambda_layer_tag.return_value = "datadog_lambda:v6.6.6"

        patcher = patch("datadog_lambda.tags._format_dd_lambda_layer_tag")
        self.mock_format_dd_lambda_layer_tag = patcher.start()
        # Mock the layer version so we don't have to update tests on every version bump
        self.mock_format_dd_lambda_layer_tag.return_value = (
            "dd_lambda_layer:datadog-python39_X.X.X"
        )
        self.addCleanup(patcher.stop)

    def test_datadog_lambda_wrapper(self):
        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}

        lambda_context = get_mock_context()

        lambda_handler(lambda_event, lambda_context)

        self.mock_threadstats_flush_distributions.assert_has_calls(
            [
                call(
                    [
                        {
                            "metric": "test.metric",
                            "points": [[ANY, [100]]],
                            "type": "distribution",
                            "host": None,
                            "device": None,
                            "tags": ANY,
                            "interval": 10,
                        }
                    ]
                )
            ]
        )
        self.mock_extract_dd_trace_context.assert_called_with(
            lambda_event, lambda_context, extractor=None, decode_authorizer_context=True
        )
        self.mock_set_correlation_ids.assert_called()
        self.mock_inject_correlation_ids.assert_called()
        self.mock_patch_all.assert_called()

    def test_datadog_lambda_wrapper_flush_to_log(self):
        os.environ["DD_FLUSH_TO_LOG"] = "True"

        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}
        lambda_handler(lambda_event, get_mock_context())

        self.mock_threadstats_flush_distributions.assert_not_called()

        del os.environ["DD_FLUSH_TO_LOG"]

    def test_datadog_lambda_wrapper_flush_in_thread(self):
        # force ThreadStats to flush in thread
        import datadog_lambda.metric as metric_module

        metric_module.lambda_stats.stop()
        metric_module.lambda_stats = ThreadStatsWriter(True)

        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            import time

            lambda_metric("test.metric", 100)
            time.sleep(11)
            # assert flushing in the thread
            self.assertEqual(self.mock_threadstats_flush_distributions.call_count, 1)
            lambda_metric("test.metric", 200)

        lambda_event = {}
        lambda_handler(lambda_event, get_mock_context())

        # assert another flushing in the end
        self.assertEqual(self.mock_threadstats_flush_distributions.call_count, 2)

        # reset ThreadStats
        metric_module.lambda_stats.stop()
        metric_module.lambda_stats = ThreadStatsWriter(False)

    def test_datadog_lambda_wrapper_not_flush_in_thread(self):
        # force ThreadStats to not flush in thread
        import datadog_lambda.metric as metric_module

        metric_module.lambda_stats.stop()
        metric_module.lambda_stats = ThreadStatsWriter(False)

        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            import time

            lambda_metric("test.metric", 100)
            time.sleep(11)
            # assert no flushing in the thread
            self.assertEqual(self.mock_threadstats_flush_distributions.call_count, 0)
            lambda_metric("test.metric", 200)

        lambda_event = {}
        lambda_handler(lambda_event, get_mock_context())

        # assert flushing in the end
        self.assertEqual(self.mock_threadstats_flush_distributions.call_count, 1)

        # reset ThreadStats
        metric_module.lambda_stats.stop()
        metric_module.lambda_stats = ThreadStatsWriter(False)

    def test_datadog_lambda_wrapper_inject_correlation_ids(self):
        os.environ["DD_LOGS_INJECTION"] = "True"

        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}
        lambda_handler(lambda_event, get_mock_context())

        self.mock_set_correlation_ids.assert_called()
        self.mock_inject_correlation_ids.assert_called()

        del os.environ["DD_LOGS_INJECTION"]

    def test_invocations_metric(self):
        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}

        lambda_handler(lambda_event, get_mock_context())

        self.mock_write_metric_point_to_stdout.assert_has_calls(
            [
                call(
                    "aws.lambda.enhanced.invocations",
                    1,
                    tags=[
                        "region:us-west-1",
                        "account_id:123457598159",
                        "functionname:python-layer-test",
                        "resource:python-layer-test:1",
                        "cold_start:true",
                        "memorysize:256",
                        "runtime:python3.9",
                        "datadog_lambda:v6.6.6",
                        "dd_lambda_layer:datadog-python39_X.X.X",
                    ],
                    timestamp=None,
                )
            ]
        )

    def test_errors_metric(self):
        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            raise RuntimeError()

        lambda_event = {}

        with self.assertRaises(RuntimeError):
            lambda_handler(lambda_event, get_mock_context())

        self.mock_write_metric_point_to_stdout.assert_has_calls(
            [
                call(
                    "aws.lambda.enhanced.invocations",
                    1,
                    tags=[
                        "region:us-west-1",
                        "account_id:123457598159",
                        "functionname:python-layer-test",
                        "resource:python-layer-test:1",
                        "cold_start:true",
                        "memorysize:256",
                        "runtime:python3.9",
                        "datadog_lambda:v6.6.6",
                        "dd_lambda_layer:datadog-python39_X.X.X",
                    ],
                    timestamp=None,
                ),
                call(
                    "aws.lambda.enhanced.errors",
                    1,
                    tags=[
                        "region:us-west-1",
                        "account_id:123457598159",
                        "functionname:python-layer-test",
                        "resource:python-layer-test:1",
                        "cold_start:true",
                        "memorysize:256",
                        "runtime:python3.9",
                        "datadog_lambda:v6.6.6",
                        "dd_lambda_layer:datadog-python39_X.X.X",
                    ],
                    timestamp=None,
                ),
            ]
        )

    @patch("datadog_lambda.wrapper.extract_trigger_tags")
    def test_5xx_sends_errors_metric_and_set_tags(self, mock_extract_trigger_tags):
        mock_extract_trigger_tags.return_value = {
            "function_trigger.event_source": "api-gateway",
            "function_trigger.event_source_arn": "arn:aws:apigateway:us-west-1::/restapis/1234567890/stages/prod",
            "http.url": "70ixmpl4fl.execute-api.us-east-2.amazonaws.com",
            "http.url_details.path": "/prod/path/to/resource",
            "http.method": "GET",
        }

        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            return {"statusCode": 500, "body": "fake response body"}

        lambda_event = {}

        lambda_handler(lambda_event, get_mock_context())

        self.mock_write_metric_point_to_stdout.assert_has_calls(
            [
                call(
                    "aws.lambda.enhanced.invocations",
                    1,
                    tags=[
                        "region:us-west-1",
                        "account_id:123457598159",
                        "functionname:python-layer-test",
                        "resource:python-layer-test:1",
                        "cold_start:true",
                        "memorysize:256",
                        "runtime:python3.9",
                        "datadog_lambda:v6.6.6",
                        "dd_lambda_layer:datadog-python39_X.X.X",
                    ],
                    timestamp=None,
                ),
                call(
                    "aws.lambda.enhanced.errors",
                    1,
                    tags=[
                        "region:us-west-1",
                        "account_id:123457598159",
                        "functionname:python-layer-test",
                        "resource:python-layer-test:1",
                        "cold_start:true",
                        "memorysize:256",
                        "runtime:python3.9",
                        "datadog_lambda:v6.6.6",
                        "dd_lambda_layer:datadog-python39_X.X.X",
                    ],
                    timestamp=None,
                ),
            ]
        )

    def test_enhanced_metrics_cold_start_tag(self):
        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}

        lambda_handler(lambda_event, get_mock_context())

        self.mock_is_cold_start.return_value = False

        lambda_handler(
            lambda_event, get_mock_context(aws_request_id="second-request-id")
        )

        self.mock_write_metric_point_to_stdout.assert_has_calls(
            [
                call(
                    "aws.lambda.enhanced.invocations",
                    1,
                    tags=[
                        "region:us-west-1",
                        "account_id:123457598159",
                        "functionname:python-layer-test",
                        "resource:python-layer-test:1",
                        "cold_start:true",
                        "memorysize:256",
                        "runtime:python3.9",
                        "datadog_lambda:v6.6.6",
                        "dd_lambda_layer:datadog-python39_X.X.X",
                    ],
                    timestamp=None,
                ),
                call(
                    "aws.lambda.enhanced.invocations",
                    1,
                    tags=[
                        "region:us-west-1",
                        "account_id:123457598159",
                        "functionname:python-layer-test",
                        "resource:python-layer-test:1",
                        "cold_start:false",
                        "memorysize:256",
                        "runtime:python3.9",
                        "datadog_lambda:v6.6.6",
                        "dd_lambda_layer:datadog-python39_X.X.X",
                    ],
                    timestamp=None,
                ),
            ]
        )

    def test_enhanced_metrics_latest(self):
        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}
        lambda_context = get_mock_context()

        lambda_context.invoked_function_arn = (
            "arn:aws:lambda:us-west-1:123457598159:function:python-layer-test:$Latest"
        )
        lambda_handler(lambda_event, lambda_context)

        self.mock_write_metric_point_to_stdout.assert_has_calls(
            [
                call(
                    "aws.lambda.enhanced.invocations",
                    1,
                    tags=[
                        "region:us-west-1",
                        "account_id:123457598159",
                        "functionname:python-layer-test",
                        "resource:python-layer-test:Latest",
                        "cold_start:true",
                        "memorysize:256",
                        "runtime:python3.9",
                        "datadog_lambda:v6.6.6",
                        "dd_lambda_layer:datadog-python39_X.X.X",
                    ],
                    timestamp=None,
                )
            ]
        )

    def test_enhanced_metrics_alias(self):
        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}
        lambda_context = get_mock_context()
        # tests wouldn't run because line was too long
        alias_arn = "arn:aws:lambda:us-west-1:123457598159:function:python-layer-test:My_alias-1"
        lambda_context.invoked_function_arn = alias_arn
        lambda_handler(lambda_event, lambda_context)

        self.mock_write_metric_point_to_stdout.assert_has_calls(
            [
                call(
                    "aws.lambda.enhanced.invocations",
                    1,
                    tags=[
                        "region:us-west-1",
                        "account_id:123457598159",
                        "functionname:python-layer-test",
                        "executedversion:1",
                        "resource:python-layer-test:My_alias-1",
                        "cold_start:true",
                        "memorysize:256",
                        "runtime:python3.9",
                        "datadog_lambda:v6.6.6",
                        "dd_lambda_layer:datadog-python39_X.X.X",
                    ],
                    timestamp=None,
                )
            ]
        )

    def test_no_enhanced_metrics_without_env_var(self):
        os.environ["DD_ENHANCED_METRICS"] = "false"

        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            raise RuntimeError()

        lambda_event = {}

        with self.assertRaises(RuntimeError):
            lambda_handler(lambda_event, get_mock_context())

        self.mock_write_metric_point_to_stdout.assert_not_called()

        del os.environ["DD_ENHANCED_METRICS"]

    def test_only_one_wrapper_in_use(self):
        patcher = patch("datadog_lambda.wrapper.submit_invocations_metric")
        self.mock_submit_invocations_metric = patcher.start()
        self.addCleanup(patcher.stop)

        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        # Turn off _force_wrap to emulate the nested wrapper scenario,
        # the second @datadog_lambda_wrapper should actually be no-op.
        datadog_lambda_wrapper._force_wrap = False

        lambda_handler_double_wrapped = datadog_lambda_wrapper(lambda_handler)

        lambda_event = {}

        lambda_handler_double_wrapped(lambda_event, get_mock_context())

        self.mock_patch_all.assert_called_once()
        self.mock_submit_invocations_metric.assert_called_once()

    def test_dd_requests_service_name_default(self):
        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            pass

        self.assertEqual(os.environ.get("DD_REQUESTS_SERVICE_NAME"), "aws.lambda")

    def test_dd_requests_service_name_set(self):
        os.environ["DD_SERVICE"] = "myAwesomeService"

        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            pass

        self.assertEqual(os.environ.get("DD_REQUESTS_SERVICE_NAME"), "myAwesomeService")
        del os.environ["DD_SERVICE"]

    def test_encode_authorizer_span(self):
        @datadog_lambda_wrapper
        def lambda_handler(event, context):
            return {
                "principalId": "foo",
                "policyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Action": "execute-api:Invoke",
                            "Effect": "Allow",
                            "Resource": "dummy",
                        },
                    ],
                },
                "context": {"scope": "still here"},
            }

        lambda_event = {}

        lambda_context = get_mock_context()
        mock_span = MagicMock()
        mock_span.context.span_id = "123"
        mock_span.context.trace_id = "456"
        mock_span.context.sampling_priority = "1"
        mock_span.context.dd_origin = None
        mock_span.start_ns = 1668127541671386817
        mock_span.duration_ns = 1e8
        lambda_handler.inferred_span = mock_span

        result = lambda_handler(lambda_event, lambda_context)
        raw_inject_data = result["context"]["_datadog"]
        self.assertIsInstance(raw_inject_data, str)
        inject_data = json.loads(base64.b64decode(raw_inject_data))
        self.assertEquals(inject_data[TraceHeader.PARENT_ID], "123")
        self.assertEquals(inject_data[TraceHeader.TRACE_ID], "456")
        self.assertEquals(inject_data[TraceHeader.SAMPLING_PRIORITY], "1")
        self.assertEquals(result["context"]["scope"], "still here")

    @patch("traceback.print_exc")
    def test_different_return_type_no_error(self, MockPrintExc):
        TEST_RESULTS = ["a str to return", 42, {"value": 42}, ["A", 42], None]
        mock_context = get_mock_context()
        for test_result in TEST_RESULTS:

            @datadog_lambda_wrapper
            def return_type_test(event, context):
                return test_result

            result = return_type_test({}, mock_context)
            self.assertEquals(result, test_result)
            self.assertFalse(MockPrintExc.called)
