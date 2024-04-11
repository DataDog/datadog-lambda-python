import os
import logging
import binascii
import time
import socket
import ujson as json

from datadog_lambda.constants import XrayDaemon, XraySubsegment, TraceContextSource

logger = logging.getLogger(__name__)


class Socket(object):
    def __init__(self):
        self.sock = None

    @property
    def host_port_tuple(self):
        if not hasattr(self, "_host_port_tuple"):
            self._host_port_tuple = self._get_xray_host_port(
                os.environ.get(XrayDaemon.XRAY_DAEMON_ADDRESS, "")
            )
        return self._host_port_tuple

    def send(self, payload):
        if not self.sock:
            self._connect()
        try:
            self.sock.send(payload.encode("utf-8"))
        except Exception as e_send:
            logger.error("Error occurred submitting to xray daemon: %s", e_send)

    def _connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setblocking(0)
        self.sock.connect(self.host_port_tuple)

    def _get_xray_host_port(self, address):
        if address == "":
            logger.debug("X-Ray daemon env var not set, not sending sub-segment")
            return None
        parts = address.split(":")
        if len(parts) <= 1:
            logger.debug("X-Ray daemon env var not set, not sending sub-segment")
            return None
        port = int(parts[1])
        host = parts[0]
        return (host, port)


sock = Socket()


def build_segment_payload(payload):
    if payload is None:
        return None
    return '{"format": "json", "version": 1}\n' + payload


def parse_xray_header(raw_trace_id):
    # Example:
    # Root=1-5e272390-8c398be037738dc042009320;Parent=94ae789b969f1cc5;Sampled=1;Lineage=c6c5b1b9:0
    logger.debug("Reading trace context from env var %s", raw_trace_id)
    if len(raw_trace_id) == 0:
        return None
    parts = raw_trace_id.split(";")
    if len(parts) < 3:
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
        },
        escape_forward_slashes=False,
    )
    return segment


def send_segment(key, metadata):
    if sock.host_port_tuple is None:
        return None
    context = parse_xray_header(
        os.environ.get(XrayDaemon.XRAY_TRACE_ID_HEADER_NAME, "")
    )
    if context is None:
        logger.debug(
            "Failed to create segment since it was not possible to get trace context from header"
        )
        return None

    # Skip adding segment, if the xray trace is going to be sampled away.
    if context["sampled"] == "0":
        logger.debug("Skipping sending metadata, x-ray trace was sampled out")
        return None
    segment = build_segment(context, key, metadata)
    segment_payload = build_segment_payload(segment)
    sock.send(segment_payload)
