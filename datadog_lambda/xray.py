import os
import logging
import json
import binascii
import time
import socket

from datadog_lambda.constants import XrayDaemon, XraySubsegment, TraceContextSource

logger = logging.getLogger(__name__)


def get_xray_host_port(adress):
    if adress == "":
        logger.debug("X-Ray daemon env var not set, not sending sub-segment")
        return None
    parts = adress.split(":")
    if len(parts) <= 1:
        logger.debug("X-Ray daemon env var not set, not sending sub-segment")
        return None
    port = int(parts[1])
    host = parts[0]
    return (host, port)


def send(host_port_tuple, payload):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        sock.connect(host_port_tuple[0], host_port_tuple[1])
        sock.send(payload.encode("utf-8"))
    except Exception as e_send:
        logger.error("Error occurred submitting to xray daemon: %s", str(e_send))
    try:
        sock.close()
    except Exception as e_close:
        logger.error("Error while closing the socket: %s", str(e_close))


def build_segment_payload(payload):
    if payload is None:
        return None
    return "{\"format\": \"json\", \"version\": 1}" + "\n" + payload


def parse_xray_header(raw_trace_id):
    # Example: Root=1-5e272390-8c398be037738dc042009320;Parent=94ae789b969f1cc5;Sampled=1
    logger.debug("Reading trace context from env var %s", raw_trace_id)
    if len(raw_trace_id) == 0:
        return None
    parts = raw_trace_id.split(";")
    if len(parts) != 3:
        return None
    root = parts[0].replace("Root=", "")
    parent = parts[1].replace("Parent=", "")
    sampled = parts[2].replace("Sampled=", "")
    if (
        len(root) == len(parts[0])
        or len(parent) == len(parts[1])
        or len(sampled) == len(parts[2])
    ):
        return None
    return {
        "parent_id": parent,
        "trace_id": root,
        "sampled": sampled,
        "source": TraceContextSource.XRAY,
    }


def generate_random_id():
    return binascii.b2a_hex(os.urandom(8)).decode("utf-8")


def build_segment(context, key, metadata):

    segment = json.dumps(
        {
            "id": generate_random_id(),
            "trace_id": context["trace_id"],
            "parent_id": context["parent_id"],
            "name": XraySubsegment.NAME,
            "start_time": time.time(),
            "end_time": time.time(),
            "type": "subsegment",
            "metadata": {
                XraySubsegment.NAMESPACE: {
                    key: metadata,
                }
            },
        }
    )
    return segment


def send_segment(key, metadata):
    host_port_tuple = get_xray_host_port(
        os.environ.get(XrayDaemon.XRAY_DAEMON_ADDRESS, "")
    )
    if host_port_tuple is None:
        return None
    context = parse_xray_header(
        os.environ.get(XrayDaemon.XRAY_TRACE_ID_HEADER_NAME, "")
    )
    if context is None:
        logger.debug(
            "Failed to create segment since it was not possible to get trace context from header"
        )
        return None
    segment = build_segment(context, key, metadata)
    segment_payload = build_segment_payload(segment)
    send(host_port_tuple, segment_payload)
