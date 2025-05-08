import errno
import logging
import os
import re
import socket
from threading import Lock

MIN_SEND_BUFFER_SIZE = 32 * 1024
log = logging.getLogger("datadog_lambda.dogstatsd")


class DogStatsd(object):
    def __init__(self):
        self._socket_lock = Lock()
        self.socket_path = None
        self.host = "localhost"
        self.port = 8125
        self.socket = None
        self.encoding = "utf-8"

    def get_socket(self, telemetry=False):
        """
        Return a connected socket.

        Note: connect the socket before assigning it to the class instance to
        avoid bad thread race conditions.
        """
        with self._socket_lock:
            self.socket = self._get_udp_socket(
                self.host,
                self.port,
            )
            return self.socket

    @classmethod
    def _ensure_min_send_buffer_size(cls, sock, min_size=MIN_SEND_BUFFER_SIZE):
        # Increase the receiving buffer size where needed (e.g. MacOS has 4k RX
        # buffers which is half of the max packet size that the client will send.
        if os.name == "posix":
            try:
                recv_buff_size = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                if recv_buff_size <= min_size:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, min_size)
                    log.debug("Socket send buffer increased to %dkb", min_size / 1024)
            finally:
                pass

    @classmethod
    def _get_udp_socket(cls, host, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(0)
        cls._ensure_min_send_buffer_size(sock)
        sock.connect((host, port))

        return sock

    def distribution(self, metric, value, tags=None, timestamp=None):
        """
        Send a global distribution value, optionally setting tags. The optional
        timestamp should be an integer representing seconds since the epoch
        (January 1, 1970, 00:00:00 UTC).

        >>> statsd.distribution("uploaded.file.size", 1445)
        >>> statsd.distribution("album.photo.count", 26, tags=["gender:female"])
        >>> statsd.distribution(
        >>>     "historic.file.count",
        >>>     5,
        >>>     timestamp=int(datetime(2020, 2, 14, 12, 0, 0).timestamp()),
        >>> )
        """
        self._report(metric, "d", value, tags, timestamp)

    def close_socket(self):
        """
        Closes connected socket if connected.
        """
        with self._socket_lock:
            if self.socket:
                try:
                    self.socket.close()
                except OSError as e:
                    log.error("Unexpected error: %s", str(e))
                self.socket = None

    def normalize_tags(self, tag_list):
        TAG_INVALID_CHARS_RE = re.compile(r"[^\w\d_\-:/\.]", re.UNICODE)
        TAG_INVALID_CHARS_SUBS = "_"
        return [
            re.sub(TAG_INVALID_CHARS_RE, TAG_INVALID_CHARS_SUBS, tag)
            for tag in tag_list
        ]

    def _serialize_metric(self, metric, metric_type, value, tags, timestamp):
        # Create/format the metric packet
        return "%s:%s|%s%s%s" % (
            metric,
            value,
            metric_type,
            ("|#" + ",".join(self.normalize_tags(tags))) if tags else "",
            ("|T" + str(int(timestamp))) if timestamp is not None else "",
        )

    def _report(self, metric, metric_type, value, tags, timestamp):
        if value is None:
            return

        payload = self._serialize_metric(metric, metric_type, value, tags, timestamp)

        # Send it
        self._send_to_server(payload)

    def _send_to_server(self, packet):
        try:
            mysocket = self.socket or self.get_socket()
            mysocket.send(packet.encode(self.encoding))
            return True
        except socket.timeout:
            # dogstatsd is overflowing, drop the packets (mimicks the UDP behaviour)
            pass
        except (socket.herror, socket.gaierror) as socket_err:
            log.warning(
                "Error submitting packet: %s, dropping the packet and closing the socket",
                socket_err,
            )
            self.close_socket()
        except socket.error as socket_err:
            if socket_err.errno == errno.EAGAIN:
                log.debug(
                    "Socket send would block: %s, dropping the packet", socket_err
                )
            elif socket_err.errno == errno.ENOBUFS:
                log.debug("Socket buffer full: %s, dropping the packet", socket_err)
            elif socket_err.errno == errno.EMSGSIZE:
                log.debug(
                    "Packet size too big (size: %d): %s, dropping the packet",
                    len(packet.encode(self.encoding)),
                    socket_err,
                )
            else:
                log.warning(
                    "Error submitting packet: %s, dropping the packet and closing the socket",
                    socket_err,
                )
                self.close_socket()
        except Exception as e:
            log.error("Unexpected error: %s", str(e))
        return False


statsd = DogStatsd()
