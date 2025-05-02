import os
import unittest
from datetime import datetime, timedelta
from unittest.mock import call, patch

from botocore.exceptions import ClientError as BotocoreClientError
from datadog.api.exceptions import ClientError

from datadog_lambda.api import KMS_ENCRYPTION_CONTEXT_KEY, decrypt_kms_api_key
from datadog_lambda.metric import (
    MetricsHandler,
    _select_metrics_handler,
    flush_stats,
    lambda_metric,
)
from datadog_lambda.tags import dd_lambda_layer_tag
from datadog_lambda.thread_stats_writer import ThreadStatsWriter


class TestLambdaMetric(unittest.TestCase):
    def setUp(self):
        lambda_stats_patcher = patch("datadog_lambda.metric.lambda_stats")
        self.mock_metric_lambda_stats = lambda_stats_patcher.start()
        self.addCleanup(lambda_stats_patcher.stop)

        stdout_metric_patcher = patch(
            "datadog_lambda.metric.write_metric_point_to_stdout"
        )
        self.mock_write_metric_point_to_stdout = stdout_metric_patcher.start()
        self.addCleanup(stdout_metric_patcher.stop)

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
    def test_select_metrics_handler_extension_despite_flush_to_logs(self):
        os.environ["DD_FLUSH_TO_LOG"] = "True"
        self.assertEqual(MetricsHandler.EXTENSION, _select_metrics_handler())
        del os.environ["DD_FLUSH_TO_LOG"]

    @patch("datadog_lambda.metric.should_use_extension", False)
    def test_select_metrics_handler_forwarder_when_flush_to_logs(self):
        os.environ["DD_FLUSH_TO_LOG"] = "True"
        self.assertEqual(MetricsHandler.FORWARDER, _select_metrics_handler())
        del os.environ["DD_FLUSH_TO_LOG"]

    @patch("datadog_lambda.metric.should_use_extension", False)
    def test_select_metrics_handler_dd_api_fallback(self):
        os.environ["DD_FLUSH_TO_LOG"] = "False"
        self.assertEqual(MetricsHandler.DATADOG_API, _select_metrics_handler())
        del os.environ["DD_FLUSH_TO_LOG"]

    @patch("datadog_lambda.metric.enable_fips_mode", True)
    @patch("datadog_lambda.metric.should_use_extension", False)
    def test_select_metrics_handler_has_no_fallback_in_fips_mode(self):
        os.environ["DD_FLUSH_TO_LOG"] = "False"
        self.assertEqual(MetricsHandler.NO_METRICS, _select_metrics_handler())
        del os.environ["DD_FLUSH_TO_LOG"]

    @patch("datadog_lambda.metric.metrics_handler", MetricsHandler.EXTENSION)
    def test_lambda_metric_goes_to_extension_with_extension_handler(self):
        lambda_metric("test", 1)
        self.mock_metric_lambda_stats.distribution.assert_has_calls(
            [call("test", 1, timestamp=None, tags=[dd_lambda_layer_tag])]
        )

    @patch("datadog_lambda.metric.metrics_handler", MetricsHandler.NO_METRICS)
    def test_lambda_metric_has_nowhere_to_go_with_no_metrics_handler(self):
        lambda_metric("test", 1)
        self.mock_metric_lambda_stats.distribution.assert_not_called()
        self.mock_write_metric_point_to_stdout.assert_not_called()

    @patch("datadog_lambda.metric.metrics_handler", MetricsHandler.EXTENSION)
    def test_lambda_metric_timestamp_with_extension(self):
        delta = timedelta(minutes=1)
        timestamp = int((datetime.now() - delta).timestamp())

        lambda_metric("test_timestamp", 1, timestamp)
        self.mock_metric_lambda_stats.distribution.assert_has_calls(
            [call("test_timestamp", 1, timestamp=timestamp, tags=[dd_lambda_layer_tag])]
        )
        self.mock_write_metric_point_to_stdout.assert_not_called()

    @patch("datadog_lambda.metric.metrics_handler", MetricsHandler.EXTENSION)
    def test_lambda_metric_datetime_with_extension(self):
        delta = timedelta(minutes=1)
        timestamp = datetime.now() - delta

        lambda_metric("test_datetime_timestamp", 0, timestamp)
        self.mock_metric_lambda_stats.distribution.assert_has_calls(
            [
                call(
                    "test_datetime_timestamp",
                    0,
                    timestamp=int(timestamp.timestamp()),
                    tags=[dd_lambda_layer_tag],
                )
            ]
        )
        self.mock_write_metric_point_to_stdout.assert_not_called()

    @patch("datadog_lambda.metric.metrics_handler", MetricsHandler.EXTENSION)
    def test_lambda_metric_invalid_timestamp_with_extension(self):
        delta = timedelta(hours=5)
        timestamp = int((datetime.now() - delta).timestamp())

        lambda_metric("test_timestamp", 1, timestamp)
        self.mock_metric_lambda_stats.distribution.assert_not_called()
        self.mock_write_metric_point_to_stdout.assert_not_called()

    @patch("datadog_lambda.metric.metrics_handler", MetricsHandler.FORWARDER)
    def test_lambda_metric_flush_to_log(self):
        lambda_metric("test", 1)
        self.mock_metric_lambda_stats.distribution.assert_not_called()
        self.mock_write_metric_point_to_stdout.assert_has_calls(
            [call("test", 1, timestamp=None, tags=[dd_lambda_layer_tag])]
        )

    @patch("datadog_lambda.metric.logger.warning")
    def test_lambda_metric_invalid_metric_name_none(self, mock_logger_warning):
        lambda_metric(None, 1)
        self.mock_metric_lambda_stats.distribution.assert_not_called()
        self.mock_write_metric_point_to_stdout.assert_not_called()
        mock_logger_warning.assert_called_once_with(
            "Ignoring metric submission. Invalid metric name: %s", None
        )

    @patch("datadog_lambda.metric.logger.warning")
    def test_lambda_metric_invalid_metric_name_not_string(self, mock_logger_warning):
        lambda_metric(123, 1)
        self.mock_metric_lambda_stats.distribution.assert_not_called()
        self.mock_write_metric_point_to_stdout.assert_not_called()
        mock_logger_warning.assert_called_once_with(
            "Ignoring metric submission. Invalid metric name: %s", 123
        )

    @patch("datadog_lambda.metric.logger.warning")
    def test_lambda_metric_non_numeric_value(self, mock_logger_warning):
        lambda_metric("test.non_numeric", "oops")
        self.mock_metric_lambda_stats.distribution.assert_not_called()
        self.mock_write_metric_point_to_stdout.assert_not_called()
        mock_logger_warning.assert_called_once_with(
            "Ignoring metric submission for metric '%s' because the value is not numeric: %r",
            "test.non_numeric",
            "oops",
        )


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

    def test_flush_stats_with_tags(self):
        lambda_stats = ThreadStatsWriter(True)
        original_constant_tags = lambda_stats.thread_stats.constant_tags.copy()
        tags = ["tag1:value1", "tag2:value2"]

        # Add a metric to be flushed
        lambda_stats.distribution("test.metric", 1, tags=["metric:tag"])

        with patch.object(
            lambda_stats.thread_stats.reporter, "flush_distributions"
        ) as mock_flush_distributions:
            lambda_stats.flush(tags)
            mock_flush_distributions.assert_called_once()
            # Verify that after flush, constant_tags is reset to original
            self.assertEqual(
                lambda_stats.thread_stats.constant_tags, original_constant_tags
            )

    def test_flush_temp_constant_tags(self):
        lambda_stats = ThreadStatsWriter(flush_in_thread=True)
        lambda_stats.thread_stats.constant_tags = ["initial:tag"]
        original_constant_tags = lambda_stats.thread_stats.constant_tags.copy()

        lambda_stats.distribution("test.metric", 1, tags=["metric:tag"])
        flush_tags = ["flush:tag1", "flush:tag2"]

        with patch.object(
            lambda_stats.thread_stats.reporter, "flush_distributions"
        ) as mock_flush_distributions:
            lambda_stats.flush(tags=flush_tags)
            mock_flush_distributions.assert_called_once()
            flushed_dists = mock_flush_distributions.call_args[0][0]

            # Expected tags: original constant_tags + flush_tags + metric tags
            expected_tags = original_constant_tags + flush_tags + ["metric:tag"]

            # Verify the tags on the metric
            self.assertEqual(len(flushed_dists), 1)
            metric = flushed_dists[0]
            self.assertEqual(sorted(metric["tags"]), sorted(expected_tags))

            # Verify that constant_tags is reset after flush
            self.assertEqual(
                lambda_stats.thread_stats.constant_tags, original_constant_tags
            )

        # Repeat to ensure tags do not accumulate over multiple flushes
        new_flush_tags = ["flush:tag3"]
        lambda_stats.distribution("test.metric2", 2, tags=["metric2:tag"])

        with patch.object(
            lambda_stats.thread_stats.reporter, "flush_distributions"
        ) as mock_flush_distributions:
            lambda_stats.flush(tags=new_flush_tags)
            mock_flush_distributions.assert_called_once()
            flushed_dists = mock_flush_distributions.call_args[0][0]
            # Expected tags for the new metric
            expected_tags = original_constant_tags + new_flush_tags + ["metric2:tag"]

            self.assertEqual(len(flushed_dists), 1)
            metric = flushed_dists[0]
            self.assertEqual(sorted(metric["tags"]), sorted(expected_tags))
            self.assertEqual(
                lambda_stats.thread_stats.constant_tags, original_constant_tags
            )


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
