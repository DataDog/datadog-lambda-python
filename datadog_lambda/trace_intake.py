from datadog_lambda.pb.span_pb2 import Span
from datadog_lambda.pb.trace_pb2 import APITrace
from datadog_lambda.pb.trace_payload_pb2 import TracePayload


class TraceConnection:
    def __init__(self, rootURL, apiKey):
        self._traceURL = "https://trace.agent.{}/api/v0.2/traces".format(rootURL)

    def send_traces(traces):
        pass

    def convert_trace(traces):
        pass


def convert_trace_to_protobuf_payload(trace):
    span_groups = {}

    for span in trace:
        trace_id = int(span["trace_id"])
        span_group = []
        if trace_id in span_groups:
            span_group = span_groups[trace_id]
        else:
            span_groups[trace_id] = span_group

        span_group.append(
            Span(
                service=span["service"],
                name=span["name"],
                resource=span["resource"],
                traceID=trace_id,
                spanID=int(span["span_id"]),
                parentID=int(span["parent_id"]),
                start=span["start"],
                duration=span["duration"],
                error=span["error"],
                meta=span["meta"],
                metrics=span["metrics"],
                type="",
            )
        )

    traces = []
    for trace_id, span_group in span_groups.items():
        first_span = span_group[0]
        traces.append(
            APITrace(
                traceID=trace_id,
                spans=span_group,
                startTime=first_span.start,
                endTime=first_span.start + first_span.duration,
            )
        )
        trace_payload = TracePayload(hostName="none", env="none", traces=traces)
    return trace_payload
