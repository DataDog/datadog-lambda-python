import unittest
import json

from unittest.mock import MagicMock, patch

from datadog_lambda.xray import get_xray_host_port, build_segment_payload, build_segment


class TestXRay(unittest.TestCase):
    def test_get_xray_host_port_empty_(self):
        result = get_xray_host_port("")
        self.assertIsNone(result)

    def test_get_xray_host_port_invalid_value(self):
        result = get_xray_host_port("myVar")
        self.assertIsNone(result)

    def test_get_xray_host_port_success(self):
        result = get_xray_host_port("mySuperHost:1000")
        self.assertEqual("mySuperHost", result[0])
        self.assertEqual(1000, result[1])

    def test_build_segment_payload_ok(self):
        exected_text = '{"format": "json", "version": 1}\nmyPayload'
        self.assertEqual(exected_text, build_segment_payload("myPayload"))

    def test_build_segment_payload_no_payload(self):
        self.assertIsNone(build_segment_payload(None))

    @patch("time.time", MagicMock(return_value=1111))
    @patch(
        "datadog_lambda.xray.generate_random_id",
        MagicMock(return_value="1234abcd"),
    )
    def test_build_segment(self):
        context = {
            "trace_id": 111000111,
            "parent_id": 222000222,
        }

        value = json.dumps({"a": "aaa", "b": "bbb"})
        result = build_segment(context, "myKey", "myValue")
        jsonResult = json.loads(result)
        metadataJson = jsonResult["metadata"]

        self.assertEqual("1234abcd", jsonResult["id"])
        self.assertEqual(1111, jsonResult["start_time"])
        self.assertEqual(1111, jsonResult["end_time"])
        self.assertEqual(111000111, jsonResult["trace_id"])
        self.assertEqual(222000222, jsonResult["parent_id"])
        self.assertEqual("datadog-metadata", jsonResult["name"])
        self.assertEqual("subsegment", jsonResult["type"])
        self.assertEqual("myValue", metadataJson["datadog"]["myKey"])
