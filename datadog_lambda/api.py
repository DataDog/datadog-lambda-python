import os
import logging
import base64
from datadog_lambda.extension import should_use_extension

logger = logging.getLogger(__name__)
KMS_ENCRYPTION_CONTEXT_KEY = "LambdaFunctionName"


def decrypt_kms_api_key(kms_client, ciphertext):
    from botocore.exceptions import ClientError

    """
    Decodes and deciphers the base64-encoded ciphertext given as a parameter using KMS.
    For this to work properly, the Lambda function must have the appropriate IAM permissions.

    Args:
        kms_client: The KMS client to use for decryption
        ciphertext (string): The base64-encoded ciphertext to decrypt
    """
    decoded_bytes = base64.b64decode(ciphertext)

    """
    When the API key is encrypted using the AWS console, the function name is added as an
    encryption context. When the API key is encrypted using the AWS CLI, no encryption context
    is added. We need to try decrypting the API key both with and without the encryption context.
    """
    # Try without encryption context, in case API key was encrypted using the AWS CLI
    function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    try:
        plaintext = kms_client.decrypt(CiphertextBlob=decoded_bytes)[
            "Plaintext"
        ].decode("utf-8")
    except ClientError:
        logger.debug(
            "Failed to decrypt ciphertext without encryption context, \
            retrying with encryption context"
        )
        # Try with encryption context, in case API key was encrypted using the AWS Console
        plaintext = kms_client.decrypt(
            CiphertextBlob=decoded_bytes,
            EncryptionContext={
                KMS_ENCRYPTION_CONTEXT_KEY: function_name,
            },
        )["Plaintext"].decode("utf-8")

    return plaintext


def init_api():
    if (
        not should_use_extension
        and not os.environ.get("DD_FLUSH_TO_LOG", "").lower() == "true"
    ):
        # Make sure that this package would always be lazy-loaded/outside from the critical path
        # since underlying packages are quite heavy to load and useless when the extension is present
        from datadog import api
        if not api._api_key:
            import boto3

            DD_API_KEY_SECRET_ARN = os.environ.get("DD_API_KEY_SECRET_ARN", "")
            DD_API_KEY_SSM_NAME = os.environ.get("DD_API_KEY_SSM_NAME", "")
            DD_KMS_API_KEY = os.environ.get("DD_KMS_API_KEY", "")
            DD_API_KEY = os.environ.get(
                "DD_API_KEY", os.environ.get("DATADOG_API_KEY", "")
            )

            if DD_API_KEY_SECRET_ARN:
                api._api_key = boto3.client("secretsmanager").get_secret_value(
                    SecretId=DD_API_KEY_SECRET_ARN
                )["SecretString"]
            elif DD_API_KEY_SSM_NAME:
                api._api_key = boto3.client("ssm").get_parameter(
                    Name=DD_API_KEY_SSM_NAME, WithDecryption=True
                )["Parameter"]["Value"]
            elif DD_KMS_API_KEY:
                kms_client = boto3.client("kms")
                api._api_key = decrypt_kms_api_key(kms_client, DD_KMS_API_KEY)
            else:
                api._api_key = DD_API_KEY

        logger.debug("Setting DATADOG_API_KEY of length %d", len(api._api_key))

        # Set DATADOG_HOST, to send data to a non-default Datadog datacenter
        api._api_host = os.environ.get(
            "DATADOG_HOST", "https://api." + os.environ.get("DD_SITE", "datadoghq.com")
        )
        logger.debug("Setting DATADOG_HOST to %s", api._api_host)

        # Unmute exceptions from datadog api client, so we can catch and handle them
        api._mute = False
