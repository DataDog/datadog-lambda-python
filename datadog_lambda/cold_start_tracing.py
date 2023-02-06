
import os
import time
from typing import List
class ImportNode(object):
    def __init__(self, name, origin, start_time_ns, end_time_ns= None):
        self.module_name = name
        self.file_name = origin
        self.start_time_ns = start_time_ns
        self.end_time_ns = end_time_ns
        self.children = []

root_nodes = []

import_stack = []

total = 0

n_spans = 0

skips = 0

def push_node(module_spec):
    global total
    total += 1
    global root_nodes
    node = ImportNode(module_spec.name, module_spec.origin, time.time_ns())
    global import_stack
    # print(f'Pushing node for {module_spec.name},{len(import_stack)} on stack, {len(root_nodes)} roots')
    if import_stack:
        import_stack[-1].children.append(node)
    import_stack.append(node)

def pop_node(fullname):
    global root_nodes
    end_time_ns = time.time_ns()
    global import_stack
    node = import_stack.pop()
    if node:
        node.end_time_ns = end_time_ns
    if not import_stack: # import_stack empty, a root node has been found
        root_nodes.append(node)
    # print(f'Poping node {len(import_stack)} left, {len(root_nodes)} roots')


class ColdStartTracer(object):

    def __init__(self, tracer, parent_span, cold_start_span_finish_time_ns, trace_ctx, min_duration = 3):
        self._tracer = tracer
        self.function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        self.parent_span = parent_span
        self.cold_start_span_finish_time_ns = cold_start_span_finish_time_ns
        self.min_duration = min_duration
        self.trace_ctx = trace_ctx

    def trace(self, root_nodes: List[ImportNode]):
        cold_start_span_start_time_ns = root_nodes[0].start_time_ns
        cold_start_span = self.create_cold_start_span(cold_start_span_start_time_ns)
        for import_node in root_nodes:
            self.trace_tree(import_node, cold_start_span)

    def trace_tree(self, import_node: ImportNode, parent_span):
        if import_node.end_time_ns - import_node.start_time_ns < self.min_duration:
            global skips
            skips += 1
            return
        span_kwargs = {
            "service": "aws.lambda",
            "resource": import_node.module_name,
            "span_type": "aws.lambda.import",
        }
        span = self._tracer.trace("aws.lambda.import", **span_kwargs)
        global n_spans
        n_spans += 1

        tags = {
            "resource_names": import_node.module_name,
            "resource.name": import_node.module_name,
            "filename": import_node.file_name,
            "operation_name": self.get_operation_name(import_node.file_name)
        }
        span.set_tags(tags)
        if parent_span:
            span.parent_id = parent_span.span_id
        span.start_ns = import_node.start_time_ns
        self.finish_ns(span, import_node.end_time_ns)
        for child_node in import_node.children:
            self.trace_tree(child_node, span)


    def create_cold_start_span(self, start_time_ns):
        span_kwargs = {
            "service": "aws.lambda",
            "resource": self.function_name,
            "span_type": "aws.lambda.load",
        }
        span = self._tracer.trace("aws.lambda.load", **span_kwargs)
        # tags = {

        # }
        # span.set_tags(tags)
        self._tracer.context_provider.activate(self.trace_ctx)  #  because it was reset by finish in wrapper
        # trace_ctx = self._tracer.current_trace_context()
        # print(f"SELF.TRACE_CONTEXT {self.trace_ctx}  Trace_ctx: {trace_ctx}")
        span.start_ns = start_time_ns
        self.finish_ns(span, self.cold_start_span_finish_time_ns)
        return span

    def finish_ns(self, span, finish_time_ns):
        span.finish(finish_time_ns / 1e9)
        self._tracer.context_provider.activate(self.trace_ctx) # reactivate required after each finish

    def get_operation_name(self, filename: str):
        if filename.startswith("/opt/"):
          return "aws.lambda.import_layer"
        elif filename.startswith("/var/runtime/"):
          return "aws.lambda.import_runtime"
        elif '/' in filename:
          return "aws.lambda.import"
        else:
          return "aws.lambda.import_core_module"

