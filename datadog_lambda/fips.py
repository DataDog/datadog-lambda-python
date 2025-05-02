import logging
import os

is_gov_region = os.environ.get("AWS_REGION", "").startswith("us-gov-")

enable_fips_mode = (
    os.environ.get(
        "DD_LAMBDA_FIPS_MODE",
        "true" if is_gov_region else "false",
    ).lower()
    == "true"
)

if is_gov_region or enable_fips_mode:
    logger = logging.getLogger(__name__)
    logger.debug(
        "Python Lambda Layer FIPS mode is %s.",
        "enabled" if enable_fips_mode else "not enabled",
    )
