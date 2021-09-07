from collections import deque
import unittest

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

    def test_distribution_no_tags(self):
        statsd.distribution("my.test.metric", 3)
        payload = self.recv()
        metrics = payload.split("\n")
        self.assertEqual(len(metrics), 1)
        self.assertEqual("my.test.metric:3|d", metrics[0])

    def test_distribution_with_tags(self):
        statsd.distribution("my.test.tags.metric", 3, tags=["taga:valuea,tagb:valueb"])
        payload = self.recv()
        metrics = payload.split("\n")
        self.assertEqual(len(metrics), 1)
        self.assertEqual("my.test.tags.metric:3|d|#taga:valuea_tagb:valueb", metrics[0])
