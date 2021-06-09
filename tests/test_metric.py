import os
import unittest

try:
    from unittest.mock import patch, call
except ImportError:
    from mock import patch, call

from botocore.exceptions import ClientError as BotocoreClientError
from datadog.api.exceptions import ClientError
from datadog_lambda.metric import (
    decrypt_kms_api_key,
    lambda_metric,
    ThreadStatsWriter,
    KMS_ENCRYPTION_CONTEXT_KEY,
)
from datadog_lambda.tags import _format_dd_lambda_layer_tag

MOCK_FUNCTION_NAME = "myFunction"


class TestLambdaMetric(unittest.TestCase):
    def setUp(self):
        patcher = patch("datadog_lambda.metric.lambda_stats")
        self.mock_metric_lambda_stats = patcher.start()
        self.addCleanup(patcher.stop)

    def test_lambda_metric_tagged_with_dd_lambda_layer(self):
        lambda_metric("test", 1)
        lambda_metric("test", 1, 123, [])
        lambda_metric("test", 1, tags=["tag1:test"])
        expected_tag = _format_dd_lambda_layer_tag()
        self.mock_metric_lambda_stats.distribution.assert_has_calls(
            [
                call("test", 1, timestamp=None, tags=[expected_tag]),
                call("test", 1, timestamp=123, tags=[expected_tag]),
                call("test", 1, timestamp=None, tags=["tag1:test", expected_tag]),
            ]
        )

    def test_lambda_metric_flush_to_log(self):
        os.environ["DD_FLUSH_TO_LOG"] = "True"

        lambda_metric("test", 1)
        self.mock_metric_lambda_stats.distribution.assert_not_called()

        del os.environ["DD_FLUSH_TO_LOG"]


class TestFlushThreadStats(unittest.TestCase):
    def setUp(self):
        patcher = patch(
            "datadog.threadstats.reporters.HttpReporter.flush_distributions"
        )
        self.mock_threadstats_flush_distributions = patcher.start()
        self.addCleanup(patcher.stop)

    def test_retry_on_remote_disconnected(self):
        # Raise the RemoteDisconnected error
        lambda_stats = ThreadStatsWriter(True)

        self.mock_threadstats_flush_distributions.side_effect = ClientError(
            "POST",
            "https://api.datadoghq.com/api/v1/distribution_points",
            "RemoteDisconnected('Remote end closed connection without response')",
        )
        lambda_stats.flush()
        self.assertEqual(self.mock_threadstats_flush_distributions.call_count, 2)


class TestDecryptKMSApiKey(unittest.TestCase):

    # An API key encrypted with KMS and encoded as a base64 string
    mock_encrypted_api_key_base64 = "MjIyMjIyMjIyMjIyMjIyMg=="

    # The encrypted API key after it has been decoded from base64
    mock_encrypted_api_key = "2222222222222222"

    # The true value of the API key after decryption by KMS
    expected_decrypted_api_key = "1111111111111111"

    def test_key_encrypted_with_encryption_context(self):
        os.environ["AWS_LAMBDA_FUNCTION_NAME"] = MOCK_FUNCTION_NAME

        class MockKMSClient:
            def decrypt(self, CiphertextBlob, EncryptionContext):
                if (
                    EncryptionContext.get(KMS_ENCRYPTION_CONTEXT_KEY)
                    != MOCK_FUNCTION_NAME
                ):
                    raise BotocoreClientError("Error", "Decrypt")
                if CiphertextBlob == self.mock_encrypted_api_key.encode("utf-8"):
                    return {
                        "Plaintext": self.expected_decrypted_api_key,
                    }

        mock_kms_client = MockKMSClient()
        decrypted_key = decrypt_kms_api_key(
            mock_kms_client, self.mock_encrypted_api_key_base64
        )
        self.assertEqual(decrypted_key, self.expected_decrypted_api_key)

        del os.environ["AWS_LAMBDA_FUNCTION_NAME"]

    def test_key_encrypted_without_encryption_context(self):
        class MockKMSClient:
            def decrypt(self, CiphertextBlob, EncryptionContext):
                if EncryptionContext.get(KMS_ENCRYPTION_CONTEXT_KEY) != None:
                    raise BotocoreClientError("Error", "Decrypt")
                if CiphertextBlob == self.mock_encrypted_api_key.encode("utf-8"):
                    return {
                        "Plaintext": self.expected_decrypted_api_key,
                    }

        mock_kms_client = MockKMSClient()
        decrypted_key = decrypt_kms_api_key(
            mock_kms_client, self.mock_encrypted_api_key_base64
        )
        self.assertEqual(decrypted_key, self.expected_decrypted_api_key)
