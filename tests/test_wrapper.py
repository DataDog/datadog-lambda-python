import base64
import json
import os
import unittest

from unittest.mock import patch, call, ANY, MagicMock
from datadog_lambda.constants import TraceHeader

import datadog_lambda.wrapper as wrapper
from datadog_lambda.metric import lambda_metric
from datadog_lambda.thread_stats_writer import ThreadStatsWriter
from ddtrace import Span, tracer
from ddtrace.internal.constants import MAX_UINT_64BITS


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
        patch("ddtrace.internal.remoteconfig.worker.RemoteConfigPoller").start()
        patch("ddtrace.internal.writer.AgentWriter.flush_queue").start()

        wrapper.datadog_lambda_wrapper._force_wrap = True
        wrapper.dd_tracing_enabled = True
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

        patcher = patch("datadog_lambda.tags.get_cold_start_tag")
        self.mock_get_cold_start_tag = patcher.start()
        self.mock_get_cold_start_tag.return_value = "cold_start:true"
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.tags.runtime_tag", "runtime:python3.9")
        self.mock_runtime_tag = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.metric.write_metric_point_to_stdout")
        self.mock_write_metric_point_to_stdout = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch(
            "datadog_lambda.tags.library_version_tag", "datadog_lambda:v6.6.6"
        )
        # Mock the layer version so we don't have to update tests on every version bump
        self.mock_library_version_tag = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch(
            "datadog_lambda.metric.dd_lambda_layer_tag",
            "dd_lambda_layer:datadog-python39_X.X.X",
        )
        # Mock the layer version so we don't have to update tests on every version bump
        self.mock_dd_lambda_layer_tag = patcher.start()
        self.addCleanup(patcher.stop)

    def test_datadog_lambda_wrapper(self):
        wrapper.dd_tracing_enabled = False

        @wrapper.datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}

        lambda_context = get_mock_context()

        lambda_handler(lambda_event, lambda_context)
        wrapper.dd_tracing_enabled = True
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
            lambda_event,
            lambda_context,
            extractor=None,
            decode_authorizer_context=False,
        )
        self.mock_set_correlation_ids.assert_called()
        self.mock_inject_correlation_ids.assert_called()
        self.mock_patch_all.assert_called()

    def test_datadog_lambda_wrapper_flush_to_log(self):
        os.environ["DD_FLUSH_TO_LOG"] = "True"

        @wrapper.datadog_lambda_wrapper
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

        @wrapper.datadog_lambda_wrapper
        def lambda_handler(event, context):
            import time

            lambda_metric("test.metric", 100)
            time.sleep(11)
            # assert flushing in the thread
            # TODO(astuyve) flaky test here, sometimes this is zero
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

        @wrapper.datadog_lambda_wrapper
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
        wrapper.dd_tracing_enabled = False

        @wrapper.datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}
        lambda_handler(lambda_event, get_mock_context())
        wrapper.dd_tracing_enabled = True
        self.mock_set_correlation_ids.assert_called()
        self.mock_inject_correlation_ids.assert_called()

        del os.environ["DD_LOGS_INJECTION"]

    def test_invocations_metric(self):
        @wrapper.datadog_lambda_wrapper
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
        @wrapper.datadog_lambda_wrapper
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

        @wrapper.datadog_lambda_wrapper
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
        @wrapper.datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}

        lambda_handler(lambda_event, get_mock_context())

        self.mock_get_cold_start_tag.return_value = "cold_start:false"

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
        @wrapper.datadog_lambda_wrapper
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
        @wrapper.datadog_lambda_wrapper
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

        @wrapper.datadog_lambda_wrapper
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

        @wrapper.datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        # Turn off _force_wrap to emulate the nested wrapper scenario,
        # the second @datadog_lambda_wrapper should actually be no-op.
        wrapper.datadog_lambda_wrapper._force_wrap = False

        lambda_handler_double_wrapped = wrapper.datadog_lambda_wrapper(lambda_handler)

        lambda_event = {}

        lambda_handler_double_wrapped(lambda_event, get_mock_context())

        self.mock_patch_all.assert_called_once()
        self.mock_submit_invocations_metric.assert_called_once()

    def test_dd_requests_service_name_default(self):
        # TODO(astuyve) this is now set by CI, so we need to null it out for this case
        os.environ["DD_SERVICE"] = "aws.lambda"

        @wrapper.datadog_lambda_wrapper
        def lambda_handler(event, context):
            pass

        self.assertEqual(os.environ.get("DD_REQUESTS_SERVICE_NAME"), "aws.lambda")

    def test_dd_requests_service_name_set(self):
        os.environ["DD_SERVICE"] = "myAwesomeService"

        @wrapper.datadog_lambda_wrapper
        def lambda_handler(event, context):
            pass

        self.assertEqual(os.environ.get("DD_REQUESTS_SERVICE_NAME"), "myAwesomeService")
        del os.environ["DD_SERVICE"]

    def test_encode_authorizer_span(self):
        @wrapper.datadog_lambda_wrapper
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
        test_span = tracer.trace("test_span")
        trace_ctx = tracer.current_trace_context()
        test_span.finish()
        lambda_handler.inferred_span = test_span
        lambda_handler.make_inferred_span = False
        result = lambda_handler(lambda_event, lambda_context)
        raw_inject_data = result["context"]["_datadog"]
        self.assertIsInstance(raw_inject_data, str)
        inject_data = json.loads(base64.b64decode(raw_inject_data))
        self.assertEqual(inject_data[TraceHeader.PARENT_ID], str(trace_ctx.span_id))
        self.assertEqual(
            inject_data[TraceHeader.TRACE_ID], str(MAX_UINT_64BITS & trace_ctx.trace_id)
        )
        self.assertEqual(inject_data[TraceHeader.SAMPLING_PRIORITY], "1")
        self.assertEqual(result["context"]["scope"], "still here")

    @patch("traceback.print_exc")
    def test_different_return_type_no_error(self, MockPrintExc):
        TEST_RESULTS = ["a str to return", 42, {"value": 42}, ["A", 42], None]
        mock_context = get_mock_context()
        for test_result in TEST_RESULTS:

            @wrapper.datadog_lambda_wrapper
            def return_type_test(event, context):
                return test_result

            result = return_type_test({}, mock_context)
            self.assertEqual(result, test_result)
            self.assertFalse(MockPrintExc.called)


class TestLambdaDecoratorSettings(unittest.TestCase):
    def test_some_envs_should_depend_on_dd_tracing_enabled(self):
        wrapper.dd_tracing_enabled = False
        os.environ[wrapper.DD_TRACE_MANAGED_SERVICES] = "true"
        os.environ[wrapper.DD_ENCODE_AUTHORIZER_CONTEXT] = "true"
        os.environ[wrapper.DD_DECODE_AUTHORIZER_CONTEXT] = "true"
        decorator = wrapper._LambdaDecorator(func=None)
        self.assertFalse(decorator.make_inferred_span)
        self.assertFalse(decorator.encode_authorizer_context)
        self.assertFalse(decorator.decode_authorizer_context)


class TestLambdaWrapperWithTraceContext(unittest.TestCase):
    xray_root = "1-5e272390-8c398be037738dc042009320"
    xray_parent = "94ae789b969f1cc5"
    xray_daemon_envvar = "localhost:1234"
    xray_trace_envvar = (
        f"Root={xray_root};Parent={xray_parent};Sampled=1;Lineage=c6c5b1b9:0"
    )

    @patch(
        "os.environ",
        {
            "AWS_XRAY_DAEMON_ADDRESS": xray_daemon_envvar,
            "_X_AMZN_TRACE_ID": xray_trace_envvar,
        },
    )
    def test_event_bridge_sqs_payload(self):
        patcher = patch("datadog_lambda.xray.send")
        mock_send = patcher.start()
        self.addCleanup(patcher.stop)

        def handler(event, context):
            return tracer.current_trace_context()

        wrapper.dd_tracing_enabled = True
        wrapped_handler = wrapper.datadog_lambda_wrapper(handler)

        event_trace_id = 3047453991382739997
        event_parent_id = 3047453991382739997
        event = {
            "headers": {
                "traceparent": (
                    f"00-0000000000000000{hex(event_trace_id)[2:]}-{hex(event_parent_id)[2:]}-01"
                ),
                "tracestate": "dd=s:1;t.dm:-1",
                "x-datadog-trace-id": str(event_trace_id),
                "x-datadog-parent-id": str(event_parent_id),
                "x-datadog-sampling-priority": "1",
            },
        }
        context = get_mock_context()

        result = wrapped_handler(event, context)
        aws_lambda_span = wrapped_handler.span

        self.assertIsNotNone(result)
        self.assertEqual(result.trace_id, event_trace_id)
        self.assertEqual(result.span_id, aws_lambda_span.span_id)
        self.assertEqual(result.sampling_priority, 1)
        mock_send.assert_called_once()
        (_, raw_payload), _ = mock_send.call_args
        payload = json.loads(raw_payload[33:])  # strip formatting prefix
        self.assertEqual(self.xray_root, payload["trace_id"])
        self.assertEqual(self.xray_parent, payload["parent_id"])
        self.assertDictEqual(
            {
                "datadog": {
                    "trace": {
                        "trace-id": str(event_trace_id),
                        "parent-id": str(event_parent_id),
                        "sampling-priority": "1",
                    },
                },
            },
            payload["metadata"],
        )


class TestLambdaWrapperFlushExtension(unittest.TestCase):
    def setUp(self):
        self.orig_environ = os.environ

    def tearDown(self):
        os.environ = self.orig_environ

    @patch("datadog_lambda.wrapper.should_use_extension", True)
    def test_local_test_envvar_flushing(self):
        flushes = []
        lambda_event = {}
        lambda_context = get_mock_context()

        def flush():
            flushes.append(1)

        for environ, flush_called in (
            ({"DD_LOCAL_TEST": "True"}, True),
            ({"DD_LOCAL_TEST": "true"}, True),
            ({"DD_LOCAL_TEST": "1"}, True),
            ({"DD_LOCAL_TEST": "False"}, False),
            ({"DD_LOCAL_TEST": "false"}, False),
            ({"DD_LOCAL_TEST": "0"}, False),
            ({"DD_LOCAL_TEST": ""}, False),
            ({}, False),
        ):
            os.environ = environ
            flushes.clear()

            @patch("datadog_lambda.wrapper.flush_extension", flush)
            @wrapper.datadog_lambda_wrapper
            def lambda_handler(event, context):
                pass

            lambda_handler(lambda_event, lambda_context)

            self.assertEqual(flush_called, len(flushes) == 1)
