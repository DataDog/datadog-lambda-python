import os
import unittest

from datadog_lambda.xray import (
    get_xray_host_port,
    build_payload
)

class TestXRay(unittest.TestCase):
    
    def test_get_xray_host_port_empty_env_var(self):
        result = get_xray_host_port("invalid_env_var")
        self.assertIsNone(result)

    def test_get_xray_host_port_invalid_value_env_var(self):
        os.environ["myVar"] = "invalueValue"
        result = get_xray_host_port("myVar")
        self.assertIsNone(result)
        del os.environ["myVar"]

    def test_get_xray_host_port_success(self):
        os.environ["myVar"] = "mySuperHost:1000"
        result = get_xray_host_port("myVar")
        self.assertEqual("mySuperHost", result[0])
        self.assertEqual(1000, result[1])
        del os.environ["myVar"]

    def test_build_payload_ok(self):
        exected_text = "{\"format\": \"json\", \"version\": 1}\nmyPayload"
        self.assertEqual(exected_text, build_payload("myPayload"))

    def test_build_payload_no_payload(self):
        self.assertIsNone(build_payload(None))

