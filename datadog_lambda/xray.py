import os
import logging

awsXrayDaemonAddressEnvVar = "AWS_XRAY_DAEMON_ADDRESS";
logger = logging.getLogger(__name__)

# class XRaySender(object):
#     def __init__(self):
#         self.host = "localhost"
#         self.port = 2000
#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         sock.setblocking(0)
#         sock.connect(XrayDeamon.HOST, XrayDeamon.PORT)
#         self.sock = sock

def get_xray_host_port(awsXrayDaemonAddressEnvVar):
    env_value = os.environ.get(awsXrayDaemonAddressEnvVar, "")
    if env_value == "":
        logger.debug("X-Ray daemon env var not set, not sending sub-segment")
        return None
    parts = env_value.split(":")
    if len(parts) <= 1:
        logger.debug("X-Ray daemon env var not set, not sending sub-segment")
        return None
    port = int(parts[1])
    host = parts[0]
    return (host, port)

def send(host_port_tuple, segment):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        sock.connect(host_port_tuple[0], host_port_tuple[1])
        sock.send(segment.encode("utf-8"))
    except Exception as e_send:
        logger.error("Error occurred submitting to xray daemon: %s", str(e_send))
    try:
        sock.close()
    except Exception as e_close:
        logger.error("Error while closing the socket: %s", str(e_close))

def build_payload(payload):
    if payload is None:
        return None
    return "{\"format\": \"json\", \"version\": 1}\n" + payload

