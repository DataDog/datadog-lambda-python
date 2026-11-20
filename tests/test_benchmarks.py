import builtins
import json
import os
import pytest

import ddtrace

from datadog_lambda import metric
from datadog_lambda import tag_object
from datadog_lambda import tracing
from datadog_lambda import trigger
from datadog_lambda import xray

from datadog_lambda.constants import XrayDaemon, XraySubsegment

from tests.utils import get_mock_context, reset_xray_connection


event_samples_dir = "tests/event_samples"
event_samples = [f[:-5] for f in os.listdir(event_samples_dir) if f.endswith(".json")]


def test_metric_write_metric_point_to_stdout(benchmark, monkeypatch):
    monkeypatch.setattr(builtins, "print", lambda *a, **k: None)
    benchmark(
        metric.write_metric_point_to_stdout,
        "metric_name",
        1,
        tags=[
            "tag1:value1",
            "tag2:value2",
            "tag3:value3",
        ],
    )


@pytest.mark.parametrize("event", event_samples)
def test_tag_object_tag_object(event, benchmark):
    with open(f"{event_samples_dir}/{event}.json") as f:
        event = json.load(f)
    span = ddtrace.trace.tracer.start_span("test")
    benchmark(tag_object.tag_object, span, "function.request", event)


@pytest.mark.parametrize("event", event_samples)
def test_tracing_create_inferred_span(event, benchmark):
    with open(f"{event_samples_dir}/{event}.json") as f:
        event = json.load(f)
    context = get_mock_context()
    benchmark(tracing.create_inferred_span, event, context)


@pytest.mark.parametrize("event", event_samples)
def test_tracing_extract_dd_trace_context(event, benchmark):
    with open(f"{event_samples_dir}/{event}.json") as f:
        event = json.load(f)
    context = get_mock_context()
    benchmark(tracing.extract_dd_trace_context, event, context)


@pytest.mark.parametrize("event", event_samples)
def test_trigger_parse_event_source(event, benchmark):
    with open(f"{event_samples_dir}/{event}.json") as f:
        event = json.load(f)
    benchmark(trigger.parse_event_source, event)


@pytest.mark.parametrize("event", event_samples)
def test_trigger_extract_trigger_tags(event, benchmark):
    with open(f"{event_samples_dir}/{event}.json") as f:
        event = json.load(f)
    context = get_mock_context()
    benchmark(trigger.extract_trigger_tags, event, context)


def test_xray_send_segment(benchmark, monkeypatch):
    reset_xray_connection()

    monkeypatch.setenv(XrayDaemon.XRAY_DAEMON_ADDRESS, "localhost:9000")
    monkeypatch.setenv(
        XrayDaemon.XRAY_TRACE_ID_HEADER_NAME,
        "Root=1-5e272390-8c398be037738dc042009320;Parent=94ae789b969f1cc5;Sampled=1;Lineage=c6c5b1b9:0",
    )

    def socket_send(*a, **k):
        sends.append(True)

    sends = []
    monkeypatch.setattr("socket.socket.send", socket_send)

    key = {
        "trace-id": "12345678901234567890123456789012",
        "parent-id": "1234567890123456",
        "sampling-priority": "1",
    }
    benchmark(xray.send_segment, XraySubsegment.TRACE_KEY, key)
    assert sends


@pytest.mark.parametrize("feature", ["false", "true"])
def test_asm_start_request_access_key_id(feature, benchmark, monkeypatch):
    # Feature overhead of the AWS access key ID tag: compare "true" to "false".
    from unittest.mock import patch

    from datadog_lambda import asm

    monkeypatch.setenv("DD_APPSEC_AWS_ACCESS_KEY_ID_TAG_ENABLED", feature)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "ASIAEXAMPLE000000001")
    monkeypatch.setattr(asm, "_aws_access_key_id", asm._UNREAD)
    with open(f"{event_samples_dir}/api-gateway.json") as f:
        event = json.load(f)
    context = get_mock_context()
    event_source = trigger.parse_event_source(event)
    trigger_tags = trigger.extract_trigger_tags(event, context)
    span = ddtrace.trace.tracer.start_span("aws.lambda")
    with patch("datadog_lambda.asm.core"):
        benchmark(asm.asm_start_request, span, event, event_source, trigger_tags)
