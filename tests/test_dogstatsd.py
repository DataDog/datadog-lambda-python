import unittest
from collections import deque

from datadog_lambda.dogstatsd import statsd


class FakeSocket(object):
    def __init__(self):
        self.payloads = deque()

    def send(self, payload):
        self.payloads.append(payload)

    def recv(self, count=1, reset_wait=False, no_wait=False):
        out = []
        for _ in range(count):
            out.append(self.payloads.popleft().decode("utf-8"))
        return "\n".join(out)

    def close(self):
        pass


class TestDogStatsd(unittest.TestCase):
    def setUp(self):
        statsd.socket = FakeSocket()

    def tearDown(self):
        statsd.close_socket()

    def recv(self, *args, **kwargs):
        return statsd.socket.recv(*args, **kwargs)

    def test_init(self):
        self.assertEqual(statsd.host, "localhost")
        self.assertEqual(statsd.port, 8125)
        self.assertEqual(statsd.encoding, "utf-8")

    def _checkOnlyOneMetric(self, value):
        payload = self.recv()
        metrics = payload.split("\n")
        self.assertEqual(len(metrics), 1)
        self.assertEqual(value, metrics[0])

    def test_distribution_no_tags(self):
        statsd.distribution("my.test.metric", 3)
        self._checkOnlyOneMetric("my.test.metric:3|d")

    def test_distribution_with_tags(self):
        statsd.distribution("my.test.tags.metric", 3, tags=["taga:valuea,tagb:valueb"])
        self._checkOnlyOneMetric("my.test.tags.metric:3|d|#taga:valuea_tagb:valueb")

    def test_distribution_with_timestamp(self):
        statsd.distribution("my.test.timestamp.metric", 9, timestamp=123456789)
        self._checkOnlyOneMetric("my.test.timestamp.metric:9|d|T123456789")
