import json
import unittest

from datadog_lambda.pb.span_pb2 import Span
from datadog_lambda.pb.trace_pb2 import APITrace
from datadog_lambda.pb.trace_payload_pb2 import TracePayload

from datadog_lambda.trace_intake import convert_trace_to_protobuf_payload

trace_json = """
[
    {
        "trace_id": "123456789",
        "span_id": "2444019482234734187",
        "parent_id": "8013457365659549622",
        "name": "calculation-long-number",
        "resource": "calculation-long-number",
        "error": 0,
        "meta": {
        "language": "javascript"
        },
        "metrics": {
        "_sample_rate": 1,
        "_sampling_priority_v1": 2
        },
        "start": 1565629816129527300,
        "duration": 261757813,
        "service": "node"
    },
    {
        "trace_id": "123456789",
        "span_id": "8013457365659549622",
        "parent_id": "10315725266185511464",
        "name": "aws.lambda",
        "resource": "aws.lambda",
        "error": 0,
        "meta": {
        "language": "javascript"
        },
        "metrics": {
        "_sample_rate": 1,
        "_sampling_priority_v1": 2
        },
        "start": 1565629815909951200,
        "duration": 481683350,
        "service": "node"
    }
    ]
"""


class TestConvertTraces(unittest.TestCase):
    def test_convert_trace_to_protobuf(self):
        trace = json.loads(trace_json)
        result = convert_trace_to_protobuf_payload(trace)
        self.assertEqual(
            result,
            TracePayload(
                hostName="none",
                env="none",
                traces=[
                    APITrace(
                        traceID=123456789,
                        startTime=1565629816129527300,
                        endTime=1565629816391285113,
                        spans=[
                            Span(
                                traceID=123456789,
                                spanID=2444019482234734187,
                                parentID=8013457365659549622,
                                name="calculation-long-number",
                                resource="calculation-long-number",
                                error=0,
                                meta={"language": "javascript"},
                                metrics={"_sample_rate": 1, "_sampling_priority_v1": 2},
                                start=1565629816129527300,
                                duration=261757813,
                                service="node",
                                type="",
                            ),
                            Span(
                                traceID=123456789,
                                spanID=8013457365659549622,
                                parentID=10315725266185511464,
                                name="aws.lambda",
                                resource="aws.lambda",
                                error=0,
                                meta={"language": "javascript"},
                                metrics={"_sample_rate": 1, "_sampling_priority_v1": 2},
                                start=1565629815909951200,
                                duration=481683350,
                                service="node",
                                type="",
                            ),
                        ],
                    )
                ],
            ),
        )
