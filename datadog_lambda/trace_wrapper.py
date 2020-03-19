import sys
from datadog_lambda.constants import SamplingPriority, TraceHeader, Source


class TraceWrapper:
    """
    TraceWrapper wraps dd-trace, to make this library usable when 
    dd-trace hasn't been installed/initialised
    """

    def __init__(self):
        self._tracer = None

    def extract(self, event):
        tracer = self._load_tracer()
        if not tracer:
            return None
        return _propagator.extract(event)

    def start_span(self, name, **kwargs):
        tracer = self._load_tracer()
        if not tracer:
            return None

        return tracer.start_span(name, **kwargs)

    def _load_tracer(self):
        if not TraceWrapper.tracer_enabled():
            return None
        try:
            if not self._tracer:
                from ddtrace import tracer
                from ddtrace.propagation.http import HTTPPropagator

                self._tracer = tracer
                self._propagator = HTTPPropagator()
        except:
            pass
        return self._tracer

    @property
    def trace_context(self):
        tracer = self._load_tracer()
        if not tracer:
            return None
        span = tracer.current_span()
        if not span:
            return None

        parent_id = span.context.span_id
        trace_id = span.context.trace_id
        return {
            "parent_id": str(parent_id),
            "trace_id": str(trace_id),
            "sampling_priority": SamplingPriority.AUTO_KEEP,
            "source": Source.DDTRACE,
        }

    @staticmethod
    def tracer_enabled():
        mods = sys.modules.keys()
        # Check whether user has imported ddtrace
        return "ddtrace" in mods


trace_wrapper = TraceWrapper()
