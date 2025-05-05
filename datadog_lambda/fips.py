import logging
import os

is_gov_region = os.environ.get("AWS_REGION", "").startswith("us-gov-")

fips_mode_enabled = (
    os.environ.get(
        "DD_LAMBDA_FIPS_MODE",
        "true" if is_gov_region else "false",
    ).lower()
    == "true"
)

if is_gov_region or fips_mode_enabled:
    logger = logging.getLogger(__name__)
    logger.debug(
        "Python Lambda Layer FIPS mode is %s.",
        "enabled" if fips_mode_enabled else "not enabled",
    )
