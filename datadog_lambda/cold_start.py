import time
import os
from importlib.abc import Loader
from typing import List

_cold_start = True
_lambda_container_initialized = False
root_nodes = []
import_stack = []


def set_cold_start():
    """Set the value of the cold start global

    This should be executed once per Lambda execution before the execution
    """
    global _cold_start
    global _lambda_container_initialized
    _cold_start = not _lambda_container_initialized
    _lambda_container_initialized = True


def is_cold_start():
    """Returns the value of the global cold_start"""
    return _cold_start


def get_cold_start_tag():
    """Returns the cold start tag to be used in metrics"""
    return "cold_start:{}".format(str(is_cold_start()).lower())


class ImportNode(object):
    def __init__(self, module_name, full_file_path, start_time_ns, end_time_ns=None):
        self.module_name = module_name
        self.full_file_path = full_file_path
        self.start_time_ns = start_time_ns
        self.end_time_ns = end_time_ns
        self.children = []


def push_node(module_name, file_path):
    node = ImportNode(module_name, file_path, time.time_ns())
    if import_stack:
        import_stack[-1].children.append(node)
    import_stack.append(node)


def pop_node(module_name):
    if not import_stack:
        return
    node = import_stack.pop()
    if node.module_name != module_name:
        return
    end_time_ns = time.time_ns()
    node.end_time_ns = end_time_ns
    if not import_stack:  # import_stack empty, a root node has been found
        root_nodes.append(node)


def wrap_exec_module(original_exec_module):
    def wrapped_method(module):
        should_pop = False
        spec = module.__spec__
        try:
            push_node(spec.name, spec.origin)
            should_pop = True
        except:
            pass
        try:
            return original_exec_module(module)
        finally:
            if should_pop:
                pop_node(spec.name)

    return wrapped_method


def wrap_load_module(original_load_module):
    def wrapped_method(fullname):
        should_pop = False
        try:
            push_node(fullname, fullname)
            should_pop = True
        except:
            pass
        try:
            return original_load_module(fullname)
        finally:
            if should_pop:
                pop_node(fullname)

    return wrapped_method


def wrap_find_spec(original_find_spec):
    def wrapped_find_spec(*args, **kwargs):
        spec = original_find_spec(*args, **kwargs)
        if spec is None:
            return None
        loader = getattr(spec, "loader", None)
        if loader is not None:
            if hasattr(loader, "exec_module") and hasattr(loader, "create_module"):
                loader.exec_module = wrap_exec_module(loader.exec_module)
            if hasattr(loader, "load_module"):  # legacy support
                loader.load_module = wrap_load_module(loader.load_module)
        return spec

    return wrapped_find_spec


class ColdStartTracer(object):
    def __init__(
        self,
        tracer,
        function_name,
        cold_start_span_finish_time_ns,
        trace_ctx,
        min_duration_ms: int,
        ignored_libs: List[str] = [],
    ):
        self._tracer = tracer
        self.function_name = function_name
        self.cold_start_span_finish_time_ns = cold_start_span_finish_time_ns
        self.min_duration_ms = min_duration_ms
        self.trace_ctx = trace_ctx
        self.ignored_libs = ignored_libs
        self.need_to_reactivate_context = True

    def trace(self, root_nodes: List[ImportNode] = root_nodes):
        if not root_nodes:
            return
        cold_start_span_start_time_ns = root_nodes[0].start_time_ns
        cold_start_span = self.create_cold_start_span(cold_start_span_start_time_ns)
        while root_nodes:
            root_node = root_nodes.pop()
            self.trace_tree(root_node, cold_start_span)
        self.finish_span(cold_start_span, self.cold_start_span_finish_time_ns)

    def trace_tree(self, import_node: ImportNode, parent_span):
        if (
            import_node.end_time_ns - import_node.start_time_ns
            < self.min_duration_ms * 1e6
            or import_node.module_name in self.ignored_libs
        ):
            return

        span = self.start_span(
            "aws.lambda.import", import_node.module_name, import_node.start_time_ns
        )
        tags = {
            "resource_names": import_node.module_name,
            "resource.name": import_node.module_name,
            "filename": import_node.full_file_path,
            "operation_name": self.get_operation_name(import_node.full_file_path),
        }
        span.set_tags(tags)
        if parent_span:
            span.parent_id = parent_span.span_id
        for child_node in import_node.children:
            self.trace_tree(child_node, span)
        self.finish_span(span, import_node.end_time_ns)

    def create_cold_start_span(self, start_time_ns):
        span = self.start_span("aws.lambda.load", self.function_name, start_time_ns)
        tags = {
            "resource_names": self.function_name,
            "resource.name": self.function_name,
            "operation_name": "aws.lambda.load",
        }
        span.set_tags(tags)
        return span

    def start_span(self, span_type, resource, start_time_ns):
        if self.need_to_reactivate_context:
            self._tracer.context_provider.activate(
                self.trace_ctx
            )  # reactivate required after each finish() call
            self.need_to_reactivate_context = False
        span_kwargs = {
            "service": "aws.lambda",
            "resource": resource,
            "span_type": span_type,
        }
        span = self._tracer.trace(span_type, **span_kwargs)
        span.start_ns = start_time_ns
        return span

    def finish_span(self, span, finish_time_ns):
        span.finish(finish_time_ns / 1e9)
        self.need_to_reactivate_context = True

    def get_operation_name(self, filename: str):
        if filename is None:
            return "aws.lambda.import_core_module"
        if not isinstance(filename, str):
            return "aws.lambda.import"
        if filename.startswith("/opt/"):
            return "aws.lambda.import_layer"
        elif filename.startswith("/var/lang/"):
            return "aws.lambda.import_runtime"
        else:
            return "aws.lambda.import"
