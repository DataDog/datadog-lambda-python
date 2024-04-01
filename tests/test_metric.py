import os
import unittest

from unittest.mock import patch, call

from botocore.exceptions import ClientError as BotocoreClientError
from datadog.api.exceptions import ClientError


from datadog_lambda.metric import lambda_metric
from datadog_lambda.api import decrypt_kms_api_key, KMS_ENCRYPTION_CONTEXT_KEY
from datadog_lambda.thread_stats_writer import ThreadStatsWriter
from datadog_lambda.tags import dd_lambda_layer_tag


class TestLambdaMetric(unittest.TestCase):
    def setUp(self):
        patcher = patch("datadog_lambda.metric.lambda_stats")
        self.mock_metric_lambda_stats = patcher.start()
        self.addCleanup(patcher.stop)

    def test_lambda_metric_tagged_with_dd_lambda_layer(self):
        lambda_metric("test", 1)
        lambda_metric("test", 1, 123, [])
        lambda_metric("test", 1, tags=["tag1:test"])
        self.mock_metric_lambda_stats.distribution.assert_has_calls(
            [
                call("test", 1, timestamp=None, tags=[dd_lambda_layer_tag]),
                call("test", 1, timestamp=123, tags=[dd_lambda_layer_tag]),
                call(
                    "test", 1, timestamp=None, tags=["tag1:test", dd_lambda_layer_tag]
                ),
            ]
        )

    # let's fake that the extension is present, this should override DD_FLUSH_TO_LOG
    @patch("datadog_lambda.metric.should_use_extension", True)
    def test_lambda_metric_flush_to_log_with_extension(self):
        os.environ["DD_FLUSH_TO_LOG"] = "True"
        lambda_metric("test", 1)
        self.mock_metric_lambda_stats.distribution.assert_has_calls(
            [call("test", 1, timestamp=None, tags=[dd_lambda_layer_tag])]
        )
        del os.environ["DD_FLUSH_TO_LOG"]

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


MOCK_FUNCTION_NAME = "myFunction"

# An API key encrypted with KMS and encoded as a base64 string
MOCK_ENCRYPTED_API_KEY_BASE64 = "MjIyMjIyMjIyMjIyMjIyMg=="

# The encrypted API key after it has been decoded from base64
MOCK_ENCRYPTED_API_KEY = "2222222222222222"

# The true value of the API key after decryption by KMS
EXPECTED_DECRYPTED_API_KEY = "1111111111111111"


class TestDecryptKMSApiKey(unittest.TestCase):
    def test_key_encrypted_with_encryption_context(self):
        os.environ["AWS_LAMBDA_FUNCTION_NAME"] = MOCK_FUNCTION_NAME

        class MockKMSClient:
            def decrypt(self, CiphertextBlob=None, EncryptionContext={}):
                if (
                    EncryptionContext.get(KMS_ENCRYPTION_CONTEXT_KEY)
                    != MOCK_FUNCTION_NAME
                ):
                    raise BotocoreClientError({}, "Decrypt")
                if CiphertextBlob == MOCK_ENCRYPTED_API_KEY.encode("utf-8"):
                    return {
                        "Plaintext": EXPECTED_DECRYPTED_API_KEY.encode("utf-8"),
                    }

        mock_kms_client = MockKMSClient()
        decrypted_key = decrypt_kms_api_key(
            mock_kms_client, MOCK_ENCRYPTED_API_KEY_BASE64
        )
        self.assertEqual(decrypted_key, EXPECTED_DECRYPTED_API_KEY)

        del os.environ["AWS_LAMBDA_FUNCTION_NAME"]

    def test_key_encrypted_without_encryption_context(self):
        class MockKMSClient:
            def decrypt(self, CiphertextBlob=None, EncryptionContext={}):
                if EncryptionContext.get(KMS_ENCRYPTION_CONTEXT_KEY) != None:
                    raise BotocoreClientError({}, "Decrypt")
                if CiphertextBlob == MOCK_ENCRYPTED_API_KEY.encode("utf-8"):
                    return {
                        "Plaintext": EXPECTED_DECRYPTED_API_KEY.encode("utf-8"),
                    }

        mock_kms_client = MockKMSClient()
        decrypted_key = decrypt_kms_api_key(
            mock_kms_client, MOCK_ENCRYPTED_API_KEY_BASE64
        )
        self.assertEqual(decrypted_key, EXPECTED_DECRYPTED_API_KEY)
