import os
import time
import unittest

from sys import modules, meta_path
from unittest.mock import MagicMock

import datadog_lambda.cold_start as cold_start
import datadog_lambda.wrapper as wrapper

from tests.utils import get_mock_context


class TestColdStartTracingSetup(unittest.TestCase):
    def test_proactive_init(self):
        cold_start._cold_start = True
        cold_start._proactive_initialization = False
        cold_start._lambda_container_initialized = False
        fifteen_seconds_ago = time.time_ns() - 15_000_000_000
        cold_start.set_cold_start(fifteen_seconds_ago)
        self.assertTrue(cold_start.is_proactive_init())
        self.assertTrue(cold_start.is_new_sandbox())
        self.assertFalse(cold_start.is_cold_start())
        self.assertEqual(
            cold_start.get_proactive_init_tag(), "proactive_initialization:true"
        )
        self.assertEqual(cold_start.get_cold_start_tag(), "cold_start:false")

    def test_cold_start(self):
        cold_start._cold_start = True
        cold_start._proactive_initialization = False
        cold_start._lambda_container_initialized = False
        one_second_ago = time.time_ns() - 1_000_000_000
        cold_start.set_cold_start(one_second_ago)
        self.assertFalse(cold_start.is_proactive_init())
        self.assertTrue(cold_start.is_new_sandbox())
        self.assertTrue(cold_start.is_cold_start())
        self.assertEqual(
            cold_start.get_proactive_init_tag(), "proactive_initialization:false"
        )
        self.assertEqual(cold_start.get_cold_start_tag(), "cold_start:true")

    def test_initialize_cold_start_tracing(self):
        cold_start._cold_start = True
        cold_start.initialize_cold_start_tracing()  # testing double wrapping
        cold_start._cold_start = True
        cold_start.initialize_cold_start_tracing()
        cold_start.reset_node_stacks()
        for module_name in ["ast", "dis", "inspect"]:
            if module_name in modules:
                del modules[module_name]
        import inspect  # import some package

        self.assertTrue(inspect.ismodule(inspect))
        self.assertEqual(len(cold_start.root_nodes), 1)
        self.assertEqual(cold_start.root_nodes[0].module_name, "inspect")

    def test_bad_importer_find_spec_attribute_error(self):
        mock_importer = object()  # AttributeError when accessing find_spec
        meta_path.append(mock_importer)
        cold_start._cold_start = True
        cold_start.initialize_cold_start_tracing()  # safe to call
        meta_path.pop()

    def test_not_wrapping_case(self):
        os.environ["DD_COLD_START_TRACING"] = "false"
        mock_importer = MagicMock()
        mock_module_spec = MagicMock()
        mock_module_spec.name = "test_name"
        mock_loader = object()
        mock_module_spec.loader = mock_loader

        def find_spec(*args, **kwargs):
            return mock_module_spec

        mock_importer.find_spec = find_spec
        meta_path.append(mock_importer)
        cold_start._cold_start = True
        cold_start.initialize_cold_start_tracing()
        self.assertFalse(mock_loader in cold_start.already_wrapped_loaders)
        meta_path.pop()
        os.environ["DD_COLD_START_TRACING"] = "true"

    def test_exec_module_failure_case(self):
        mock_importer = MagicMock()
        mock_module_spec = MagicMock()
        mock_module_spec.name = "test_name"
        mock_loader = MagicMock()

        def bad_exec_module(*args, **kwargs):
            raise Exception("Module failed to load")

        mock_loader.exec_module = bad_exec_module
        mock_module_spec.loader = mock_loader

        def find_spec(*args, **kwargs):
            return mock_module_spec

        mock_importer.find_spec = find_spec
        meta_path.insert(0, mock_importer)
        cold_start._cold_start = True
        cold_start.initialize_cold_start_tracing()
        cold_start.reset_node_stacks()
        try:
            import dummy_module
        except Exception as e:
            self.assertEqual(str(e), "Module failed to load")
        meta_path.pop(0)  # clean up first before checking test results
        self.assertEqual(
            len(cold_start.root_nodes), 1
        )  # push_node should have pushed the node
        self.assertEqual(cold_start.root_nodes[0].module_name, mock_module_spec.name)


class TestColdStartTracer(unittest.TestCase):
    def setUp(self) -> None:
        mock_tracer = MagicMock()
        self.output_spans = []
        self.shared_mock_span = MagicMock()
        self.shared_mock_span.current_spans = []
        self.finish_call_count = 0

        def _finish(finish_time_s):
            module_name = self.shared_mock_span.current_spans.pop()
            self.output_spans.append(module_name)
            self.finish_call_count += 1

        self.shared_mock_span.finish = _finish

        def _trace(*args, **kwargs):
            module_name = kwargs["resource"]
            self.shared_mock_span.current_spans.append(module_name)
            return self.shared_mock_span

        mock_tracer.trace = _trace
        self.mock_activate = MagicMock()
        mock_tracer.context_provider.activate = self.mock_activate
        self.mock_trace_ctx = MagicMock()
        self.first_node_start_time_ns = 1676217209680116000
        self.cold_start_tracer = cold_start.ColdStartTracer(
            mock_tracer,
            "unittest_cold_start",
            self.first_node_start_time_ns + 2e9,
            self.mock_trace_ctx,
            3,
            ["ignored_module_a", "ignored_module_b"],
        )
        self.test_time_unit = (self.cold_start_tracer.min_duration_ms + 1) * 1e6

    def test_trace_empty_root_nodes(self):
        self.cold_start_tracer.trace([])
        self.assertEqual(len(self.output_spans), 0)

    def test_trace_one_root_node_no_children(self):
        node_0 = cold_start.ImportNode("node_0", None, self.first_node_start_time_ns)
        node_0.end_time_ns = self.first_node_start_time_ns + 4e6
        self.cold_start_tracer.trace([node_0])
        self.mock_activate.assert_called_once_with(self.mock_trace_ctx)
        self.assertEqual(self.output_spans, ["node_0", "unittest_cold_start"])

    def test_trace_one_root_node_with_children(self):
        node_0 = cold_start.ImportNode("node_0", None, self.first_node_start_time_ns)
        node_0.end_time_ns = self.first_node_start_time_ns + self.test_time_unit * 2
        node_1 = cold_start.ImportNode("node_1", None, self.first_node_start_time_ns)
        node_1.end_time_ns = self.first_node_start_time_ns + self.test_time_unit
        node_2 = cold_start.ImportNode(
            "node_2", None, self.first_node_start_time_ns + self.test_time_unit
        )
        node_2.end_time_ns = self.first_node_start_time_ns + self.test_time_unit * 2
        node_3 = cold_start.ImportNode("node_3", None, self.first_node_start_time_ns)
        node_3.end_time_ns = self.first_node_start_time_ns + self.test_time_unit
        nodes = [node_0]
        node_0.children = [node_1, node_2]
        node_1.children = [node_3]
        self.cold_start_tracer.trace(nodes)
        self.mock_activate.assert_called_with(self.mock_trace_ctx)
        self.assertEqual(self.finish_call_count, 5)
        self.assertEqual(self.mock_activate.call_count, 2)
        self.assertEqual(
            self.output_spans,
            ["node_3", "node_1", "node_2", "node_0", "unittest_cold_start"],
        )

    def test_trace_multiple_root_nodes(self):
        node_0 = cold_start.ImportNode("node_0", None, self.first_node_start_time_ns)
        node_0.end_time_ns = self.first_node_start_time_ns + self.test_time_unit * 2
        node_1 = cold_start.ImportNode(
            "node_1", None, self.first_node_start_time_ns + self.test_time_unit * 2
        )
        node_1.end_time_ns = self.first_node_start_time_ns + self.test_time_unit * 3
        node_2 = cold_start.ImportNode("node_2", None, self.first_node_start_time_ns)
        node_2.end_time_ns = self.first_node_start_time_ns + self.test_time_unit
        node_3 = cold_start.ImportNode(
            "node_3", None, self.first_node_start_time_ns + self.test_time_unit
        )
        node_3.end_time_ns = self.first_node_start_time_ns + self.test_time_unit * 2
        node_4 = cold_start.ImportNode(
            "node_4", None, self.first_node_start_time_ns + self.test_time_unit * 2
        )
        node_4.end_time_ns = self.first_node_start_time_ns + self.test_time_unit * 3
        nodes = [node_0, node_1]
        node_0.children = [node_2, node_3]
        node_1.children = [node_4]
        self.cold_start_tracer.trace(nodes)
        self.mock_activate.assert_called_with(self.mock_trace_ctx)
        self.assertEqual(self.finish_call_count, 6)
        self.assertEqual(self.mock_activate.call_count, 3)
        self.assertEqual(
            self.output_spans,
            ["node_4", "node_1", "node_2", "node_3", "node_0", "unittest_cold_start"],
        )

    def test_trace_min_duration(self):
        node_0 = cold_start.ImportNode("node_0", None, self.first_node_start_time_ns)
        node_0.end_time_ns = (
            self.first_node_start_time_ns
            + self.cold_start_tracer.min_duration_ms * 1e6
            - 1e5
        )
        self.cold_start_tracer.trace([node_0])
        self.mock_activate.assert_called_once_with(self.mock_trace_ctx)
        self.assertEqual(self.output_spans, ["unittest_cold_start"])

    def test_trace_ignore_libs(self):
        node_0 = cold_start.ImportNode("node_0", None, self.first_node_start_time_ns)
        node_0.end_time_ns = self.first_node_start_time_ns + self.test_time_unit
        node_1 = cold_start.ImportNode(
            "ignored_module_a",
            None,
            self.first_node_start_time_ns + self.test_time_unit,
        )
        node_1.end_time_ns = self.first_node_start_time_ns + self.test_time_unit * 2
        node_2 = cold_start.ImportNode(
            "ignored_module_b", None, self.first_node_start_time_ns
        )
        node_2.end_time_ns = self.first_node_start_time_ns + self.test_time_unit
        nodes = [node_0, node_1]
        node_0.children = [node_2]
        self.cold_start_tracer.trace(nodes)
        self.mock_activate.assert_called_once_with(self.mock_trace_ctx)
        self.assertEqual(self.output_spans, ["node_0", "unittest_cold_start"])


def test_lazy_loaded_package_imports(monkeypatch):
    spans = []

    def finish(span):
        spans.append(span)

    monkeypatch.setattr(wrapper.tracer, "_on_span_finish", finish)
    monkeypatch.setattr(wrapper, "is_new_sandbox", lambda: True)
    monkeypatch.setattr("datadog_lambda.config.Config.trace_enabled", True)
    monkeypatch.setenv(
        "DD_COLD_START_TRACE_SKIP_LIB", "ddtrace.contrib.logging,datadog_lambda.wrapper"
    )
    monkeypatch.setenv("DD_MIN_COLD_START_DURATION", "0")

    @wrapper.datadog_lambda_wrapper
    def handler(event, context):
        import tabnanny

    lambda_context = get_mock_context()

    handler.cold_start_tracing = True
    handler({}, lambda_context)

    function_span = import_span = None
    for span in spans:
        if span.resource == "tabnanny":
            import_span = span
        elif span.name == "aws.lambda":
            function_span = span

    assert function_span is not None
    assert import_span is not None
    assert import_span.parent_id == function_span.span_id
