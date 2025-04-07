import os


def current_region() -> str:
    return os.environ.get("AWS_REGION", "")


def running_in_gov_region() -> bool:
    return current_region().startswith("us-gov-")
