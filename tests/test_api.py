import os
import unittest
from unittest.mock import patch, MagicMock

import datadog_lambda.api as api

class TestDatadogLambdaAPI(unittest.TestCase):
    def setUp(self):
        api.api_key = None
        self.env_patcher = patch.dict(
            os.environ,
            {
                "DD_API_KEY_SECRET_ARN": "",
                "DD_API_KEY_SSM_NAME": "",
                "DD_KMS_API_KEY": "",
                "DD_API_KEY": "",
                "DATADOG_API_KEY": "",
                "AWS_REGION": "",
            },
            clear=True,
        )
        self.env_patcher.start()

    @patch("boto3.client")
    def test_secrets_manager_fips_endpoint(self, mock_boto3_client):
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {"SecretString": "test-api-key"}
        mock_boto3_client.return_value = mock_client

        os.environ["AWS_REGION"] = "us-gov-east-1"
        os.environ["DD_API_KEY_SECRET_ARN"] = "test-secrets-arn"

        api_key = api.get_api_key()

        mock_boto3_client.assert_called_with(
            "secretsmanager",
            endpoint_url="https://secretsmanager-fips.us-gov-east-1.amazonaws.com",
        )
        self.assertEqual(api_key, "test-api-key")

    @patch("boto3.client")
    def test_ssm_fips_endpoint(self, mock_boto3_client):
        mock_client = MagicMock()
        mock_client.get_parameter.return_value = {
            "Parameter": {"Value": "test-api-key"}
        }
        mock_boto3_client.return_value = mock_client

        os.environ["AWS_REGION"] = "us-gov-west-1"
        os.environ["DD_API_KEY_SSM_NAME"] = "test-ssm-param"

        api_key = api.get_api_key()

        mock_boto3_client.assert_called_with(
            "ssm", endpoint_url="https://ssm-fips.us-gov-west-1.amazonaws.com"
        )
        self.assertEqual(api_key, "test-api-key")

    @patch("boto3.client")
    @patch("datadog_lambda.api.decrypt_kms_api_key")
    def test_kms_fips_endpoint(self, mock_decrypt_kms, mock_boto3_client):
        mock_client = MagicMock()
        mock_boto3_client.return_value = mock_client
        mock_decrypt_kms.return_value = "test-api-key"

        os.environ["AWS_REGION"] = "us-gov-west-1"
        os.environ["DD_KMS_API_KEY"] = "encrypted-api-key"

        api_key = api.get_api_key()

        mock_boto3_client.assert_called_with(
            "kms", endpoint_url="https://kms-fips.us-gov-west-1.amazonaws.com"
        )
        self.assertEqual(api_key, "test-api-key")

    @patch("boto3.client")
    def test_no_fips_for_standard_regions(self, mock_boto3_client):
        mock_client = MagicMock()
        mock_client.get_secret_value.return_value = {"SecretString": "test-api-key"}
        mock_boto3_client.return_value = mock_client
