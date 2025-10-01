import base64
import json
import os
import unittest
import importlib

from unittest.mock import MagicMock, patch, call, ANY
from datadog_lambda.constants import TraceHeader

import datadog_lambda.wrapper as wrapper
import datadog_lambda.xray as xray

from datadog_lambda.config import config
from datadog_lambda.metric import lambda_metric
from datadog_lambda.thread_stats_writer import ThreadStatsWriter
from ddtrace.trace import Span, tracer
from ddtrace.internal.constants import MAX_UINT_64BITS

from tests.utils import get_mock_context, reset_xray_connection


class TestDatadogLambdaWrapper(unittest.TestCase):
    def setUp(self):
        # Force @datadog_lambda_wrapper to always create a real
        # (not no-op) wrapper.
        patch("ddtrace.internal.remoteconfig.worker.RemoteConfigPoller").start()
        patch("ddtrace.internal.writer.AgentWriter.flush_queue").start()

        wrapper.datadog_lambda_wrapper._force_wrap = True
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

    @patch("datadog_lambda.config.Config.trace_enabled", False)
    def test_datadog_lambda_wrapper(self):
        @wrapper.datadog_lambda_wrapper
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
            lambda_event,
            lambda_context,
            extractor=None,
            decode_authorizer_context=False,
        )
        self.mock_set_correlation_ids.assert_called()
        self.mock_inject_correlation_ids.assert_called()

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

    @patch("datadog_lambda.config.Config.trace_enabled", False)
    def test_datadog_lambda_wrapper_inject_correlation_ids(self):
        os.environ["DD_LOGS_INJECTION"] = "True"

        @wrapper.datadog_lambda_wrapper
        def lambda_handler(event, context):
            lambda_metric("test.metric", 100)

        lambda_event = {}
        lambda_handler(lambda_event, get_mock_context())
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
                        "resource:python-layer-test",
                        "memorysize:256",
                        "cold_start:true",
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
                        "resource:python-layer-test",
                        "memorysize:256",
                        "cold_start:true",
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
                        "resource:python-layer-test",
                        "memorysize:256",
                        "cold_start:true",
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
            "http.url": "https://70ixmpl4fl.execute-api.us-east-2.amazonaws.com",
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
                        "resource:python-layer-test",
                        "memorysize:256",
                        "cold_start:true",
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
                        "resource:python-layer-test",
                        "memorysize:256",
                        "cold_start:true",
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
                        "resource:python-layer-test",
                        "memorysize:256",
                        "cold_start:true",
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
                        "resource:python-layer-test",
                        "memorysize:256",
                        "cold_start:false",
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
                        "memorysize:256",
                        "cold_start:true",
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
                        "memorysize:256",
                        "cold_start:true",
                        "runtime:python3.9",
                        "datadog_lambda:v6.6.6",
                        "dd_lambda_layer:datadog-python39_X.X.X",
                    ],
                    timestamp=None,
                )
            ]
        )

    @patch("datadog_lambda.config.Config.enhanced_metrics_enabled", False)
    def test_no_enhanced_metrics_without_env_var(self):
        @wrapper.datadog_lambda_wrapper
        def lambda_handler(event, context):
            raise RuntimeError()

        lambda_event = {}

        with self.assertRaises(RuntimeError):
            lambda_handler(lambda_event, get_mock_context())

        self.mock_write_metric_point_to_stdout.assert_not_called()

    def test_only_one_wrapper_in_use(self):
        patcher = patch("datadog_lambda.metric.submit_invocations_metric")
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

    @patch("datadog_lambda.config.Config.make_inferred_span", False)
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
        trace_ctx.sampling_priority = 1
        test_span.finish()
        lambda_handler.inferred_span = test_span
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
        reset_xray_connection()

        patcher = patch("datadog_lambda.xray.sock.send")
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
        (raw_payload,), _ = mock_send.call_args
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
    @patch("datadog_lambda.config.Config.local_test", True)
    @patch("datadog_lambda.wrapper.should_use_extension", True)
    def test_local_test_true_flushing(self):
        flushes = []
        lambda_event = {}
        lambda_context = get_mock_context()

        def flush():
            flushes.append(1)

        @patch("datadog_lambda.wrapper.flush_extension", flush)
        @wrapper.datadog_lambda_wrapper
        def lambda_handler(event, context):
            pass

        lambda_handler(lambda_event, lambda_context)

        self.assertEqual(len(flushes), 1)

    @patch("datadog_lambda.config.Config.local_test", False)
    @patch("datadog_lambda.wrapper.should_use_extension", True)
    def test_local_test_false_flushing(self):
        flushes = []
        lambda_event = {}
        lambda_context = get_mock_context()

        def flush():
            flushes.append(1)

        @patch("datadog_lambda.wrapper.flush_extension", flush)
        @wrapper.datadog_lambda_wrapper
        def lambda_handler(event, context):
            pass

        lambda_handler(lambda_event, lambda_context)

        self.assertEqual(len(flushes), 0)


class TestLambdaWrapperAppsecBlocking(unittest.TestCase):
    def setUp(self):
        os.environ["DD_APPSEC_ENABLED"] = "true"
        os.environ["DD_TRACE_ENABLED"] = "true"

        importlib.reload(wrapper)

        self.addCleanup(os.environ.pop, "DD_APPSEC_ENABLED", None)
        self.addCleanup(os.environ.pop, "DD_TRACE_ENABLED", None)
        self.addCleanup(lambda: importlib.reload(wrapper))

        patcher = patch("datadog_lambda.wrapper.asm_set_context")
        self.mock_asm_set_context = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.wrapper.asm_start_request")
        self.mock_asm_start_request = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.wrapper.asm_start_response")
        self.mock_asm_start_response = patcher.start()
        self.addCleanup(patcher.stop)

        patcher = patch("datadog_lambda.wrapper.get_asm_blocked_response")
        self.mock_get_asm_blocking_response = patcher.start()
        self.addCleanup(patcher.stop)

        with open("tests/event_samples/api-gateway.json") as f:
            self.api_gateway_request = json.loads(f.read())

        self.fake_blocking_response = {
            "statusCode": "403",
            "headers": {
                "Content-Type": "application/json",
            },
            "body": '{"message": "Blocked by AppSec"}',
            "isBase64Encoded": False,
        }

    def test_blocking_before(self):
        self.mock_get_asm_blocking_response.return_value = self.fake_blocking_response

        mock_handler = MagicMock()

        lambda_handler = wrapper.datadog_lambda_wrapper(mock_handler)

        response = lambda_handler(self.api_gateway_request, get_mock_context())
        self.assertEqual(response, self.fake_blocking_response)

        mock_handler.assert_not_called()

        self.mock_asm_set_context.assert_called_once()
        self.mock_asm_start_request.assert_called_once()
        self.mock_asm_start_response.assert_not_called()

        assert lambda_handler.span.get_tag("http.status_code") == "403"

    def test_blocking_during(self):
        self.mock_get_asm_blocking_response.return_value = None

        def lambda_handler(event, context):
            self.mock_get_asm_blocking_response.return_value = (
                self.fake_blocking_response
            )
            raise wrapper.BlockingException()

        lambda_handler = wrapper.datadog_lambda_wrapper(lambda_handler)

        response = lambda_handler(self.api_gateway_request, get_mock_context())
        self.assertEqual(response, self.fake_blocking_response)

        self.mock_asm_set_context.assert_called_once()
        self.mock_asm_start_request.assert_called_once()
        self.mock_asm_start_response.assert_not_called()

        assert lambda_handler.span.get_tag("http.status_code") == "403"

    def test_blocking_after(self):
        self.mock_get_asm_blocking_response.return_value = None

        def lambda_handler(event, context):
            self.mock_get_asm_blocking_response.return_value = (
                self.fake_blocking_response
            )
            return {
                "statusCode": 200,
                "body": "This should not be returned",
            }

        lambda_handler = wrapper.datadog_lambda_wrapper(lambda_handler)

        response = lambda_handler(self.api_gateway_request, get_mock_context())
        self.assertEqual(response, self.fake_blocking_response)

        self.mock_asm_set_context.assert_called_once()
        self.mock_asm_start_request.assert_called_once()
        self.mock_asm_start_response.assert_called_once()

        assert lambda_handler.span.get_tag("http.status_code") == "403"

    def test_no_blocking_appsec_disabled(self):
        os.environ["DD_APPSEC_ENABLED"] = "false"

        importlib.reload(wrapper)

        self.mock_get_asm_blocking_response.return_value = self.fake_blocking_response

        expected_response = {
            "statusCode": 200,
            "body": "This should be returned",
        }

        def lambda_handler(event, context):
            return expected_response

        lambda_handler = wrapper.datadog_lambda_wrapper(lambda_handler)

        response = lambda_handler(self.api_gateway_request, get_mock_context())
        self.assertEqual(response, expected_response)

        self.mock_get_asm_blocking_response.assert_not_called()
        self.mock_asm_set_context.assert_not_called()
        self.mock_asm_start_request.assert_not_called()
        self.mock_asm_start_response.assert_not_called()

        assert lambda_handler.span.get_tag("http.status_code") == "200"


@patch("datadog_lambda.config.Config.exception_replay_enabled", True)
def test_exception_replay_enabled(monkeypatch):
    importlib.reload(wrapper)

    original_SpanExceptionHandler_enable = wrapper.SpanExceptionHandler.enable
    SpanExceptionHandler_enable_calls = []

    def SpanExceptionHandler_enable(*args, **kwargs):
        SpanExceptionHandler_enable_calls.append((args, kwargs))
        return original_SpanExceptionHandler_enable(*args, **kwargs)

    original_SignalUploader_periodic = wrapper.SignalUploader.periodic
    SignalUploader_periodic_calls = []

    def SignalUploader_periodic(*args, **kwargs):
        SignalUploader_periodic_calls.append((args, kwargs))
        return original_SignalUploader_periodic(*args, **kwargs)

    monkeypatch.setattr(
        "datadog_lambda.wrapper.SpanExceptionHandler.enable",
        SpanExceptionHandler_enable,
    )
    monkeypatch.setattr(
        "datadog_lambda.wrapper.SignalUploader.periodic", SignalUploader_periodic
    )

    expected_response = {
        "statusCode": 200,
        "body": "This should be returned",
    }

    @wrapper.datadog_lambda_wrapper
    def lambda_handler(event, context):
        return expected_response

    response = lambda_handler({}, get_mock_context())

    assert response == expected_response
    assert len(SpanExceptionHandler_enable_calls) == 1
    assert len(SignalUploader_periodic_calls) == 1


@patch("datadog_lambda.config.Config.profiling_enabled", True)
def test_profiling_enabled(monkeypatch):
    importlib.reload(wrapper)

    original_Profiler_start = wrapper.profiler.Profiler.start
    Profiler_start_calls = []

    def Profiler_start(*args, **kwargs):
        Profiler_start_calls.append((args, kwargs))
        return original_Profiler_start(*args, **kwargs)

    monkeypatch.setattr("datadog_lambda.wrapper.is_new_sandbox", lambda: True)
    monkeypatch.setattr(
        "datadog_lambda.wrapper.profiler.Profiler.start", Profiler_start
    )

    expected_response = {
        "statusCode": 200,
        "body": "This should be returned",
    }

    @wrapper.datadog_lambda_wrapper
    def lambda_handler(event, context):
        return expected_response

    response = lambda_handler({}, get_mock_context())

    assert response == expected_response
    assert len(Profiler_start_calls) == 1


@patch("datadog_lambda.config.Config.llmobs_enabled", True)
def test_llmobs_enabled(monkeypatch):
    importlib.reload(wrapper)

    original_LLMObs_enable = wrapper.LLMObs.enable
    LLMObs_enable_calls = []

    def LLMObs_enable(*args, **kwargs):
        LLMObs_enable_calls.append((args, kwargs))
        return original_LLMObs_enable(*args, **kwargs)

    original_LLMObs_flush = wrapper.LLMObs.flush
    LLMObs_flush_calls = []

    def LLMObs_flush(*args, **kwargs):
        LLMObs_flush_calls.append((args, kwargs))
        return original_LLMObs_flush(*args, **kwargs)

    monkeypatch.setattr("datadog_lambda.wrapper.is_new_sandbox", lambda: True)
    monkeypatch.setattr("datadog_lambda.wrapper.LLMObs.enable", LLMObs_enable)
    monkeypatch.setattr("datadog_lambda.wrapper.LLMObs.flush", LLMObs_flush)

    expected_response = {
        "statusCode": 200,
        "body": "This should be returned",
    }

    @wrapper.datadog_lambda_wrapper
    def lambda_handler(event, context):
        return expected_response

    response = lambda_handler({}, get_mock_context())

    assert response == expected_response
    assert len(LLMObs_enable_calls) == 1
    assert len(LLMObs_flush_calls) == 1
