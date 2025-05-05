import logging
import os

from datadog_lambda.fips import fips_mode_enabled

logger = logging.getLogger(__name__)
KMS_ENCRYPTION_CONTEXT_KEY = "LambdaFunctionName"
api_key = None


def decrypt_kms_api_key(kms_client, ciphertext):
    import base64

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


def get_api_key() -> str:
    """
    Gets the Datadog API key from the environment variables or secrets manager.
    Extracts the result to a global value to avoid repeated calls to the
    secrets manager from different products.
    """
    global api_key
    if api_key:
        return api_key

    DD_API_KEY_SECRET_ARN = os.environ.get("DD_API_KEY_SECRET_ARN", "")
    DD_API_KEY_SSM_NAME = os.environ.get("DD_API_KEY_SSM_NAME", "")
    DD_KMS_API_KEY = os.environ.get("DD_KMS_API_KEY", "")
    DD_API_KEY = os.environ.get("DD_API_KEY", os.environ.get("DATADOG_API_KEY", ""))

    LAMBDA_REGION = os.environ.get("AWS_REGION", "")
    if fips_mode_enabled:
        logger.debug(
            "FIPS mode is enabled, using FIPS endpoints for secrets management."
        )

    if DD_API_KEY_SECRET_ARN:
        # Secrets manager endpoints: https://docs.aws.amazon.com/general/latest/gr/asm.html
        try:
            secrets_region = DD_API_KEY_SECRET_ARN.split(":")[3]
        except Exception:
            logger.debug(
                "Invalid secret arn in DD_API_KEY_SECRET_ARN. Unable to get API key."
            )
            return ""
        endpoint_url = (
            f"https://secretsmanager-fips.{secrets_region}.amazonaws.com"
            if fips_mode_enabled
            else None
        )
        secrets_manager_client = _boto3_client(
            "secretsmanager", endpoint_url=endpoint_url, region_name=secrets_region
        )
        api_key = secrets_manager_client.get_secret_value(
            SecretId=DD_API_KEY_SECRET_ARN
        )["SecretString"]
    elif DD_API_KEY_SSM_NAME:
        # SSM endpoints: https://docs.aws.amazon.com/general/latest/gr/ssm.html
        fips_endpoint = (
            f"https://ssm-fips.{LAMBDA_REGION}.amazonaws.com"
            if fips_mode_enabled
            else None
        )
        ssm_client = _boto3_client("ssm", endpoint_url=fips_endpoint)
        api_key = ssm_client.get_parameter(
            Name=DD_API_KEY_SSM_NAME, WithDecryption=True
        )["Parameter"]["Value"]
    elif DD_KMS_API_KEY:
        # KMS endpoints: https://docs.aws.amazon.com/general/latest/gr/kms.html
        fips_endpoint = (
            f"https://kms-fips.{LAMBDA_REGION}.amazonaws.com"
            if fips_mode_enabled
            else None
        )
        kms_client = _boto3_client("kms", endpoint_url=fips_endpoint)
        api_key = decrypt_kms_api_key(kms_client, DD_KMS_API_KEY)
    else:
        api_key = DD_API_KEY

    return api_key


def init_api():
    if not os.environ.get("DD_FLUSH_TO_LOG", "").lower() == "true":
        # Make sure that this package would always be lazy-loaded/outside from the critical path
        # since underlying packages are quite heavy to load
        # and useless with the extension unless sending metrics with timestamps
        from datadog import api

        if not api._api_key:
            api._api_key = get_api_key()

        logger.debug("Setting DATADOG_API_KEY of length %d", len(api._api_key))

        # Set DATADOG_HOST, to send data to a non-default Datadog datacenter
        api._api_host = os.environ.get(
            "DATADOG_HOST", "https://api." + os.environ.get("DD_SITE", "datadoghq.com")
        )
        logger.debug("Setting DATADOG_HOST to %s", api._api_host)

        # Unmute exceptions from datadog api client, so we can catch and handle them
        api._mute = False


def _boto3_client(*args, **kwargs):
    import botocore.session

    return botocore.session.get_session().create_client(*args, **kwargs)
