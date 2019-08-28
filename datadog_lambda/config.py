import os
import boto3
import base64

API_KEY = None
API_HOST = None


def get_config():
    global API_KEY, API_HOST
    if API_KEY:
        return API_KEY, API_HOST
    # Decrypt code should run once and variables stored outside of the function
    # handler so that these are decrypted once per container
    DD_KMS_API_KEY = os.environ.get("DD_KMS_API_KEY")
    if DD_KMS_API_KEY:
        DD_KMS_API_KEY = boto3.client("kms").decrypt(
            CiphertextBlob=base64.b64decode(DD_KMS_API_KEY)
        )["Plaintext"]

    # Set API Key and Host in the module, so they only set once per container
    API_KEY = os.environ.get(
        "DATADOG_API_KEY", os.environ.get("DD_API_KEY", DD_KMS_API_KEY)
    )

    API_HOST = os.environ.get(
        "DATADOG_HOST", os.environ.get("DD_SITE", "datadoghq.com")
    )
    return API_KEY, API_HOST
