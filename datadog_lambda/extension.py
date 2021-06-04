import logging
import requests
from os import path

AGENT_URL = "http://127.0.0.1:8124"
HELLO_PATH = "/lambda/hello"
FLUSH_PATH = "/lambda/flush"
EXTENSION_PATH = "/opt/extensions/datadog-agent"

logger = logging.getLogger(__name__)

def is_extension_running():
    if not path.exists(EXTENSION_PATH):
        return False
    try:
        requests.get(AGENT_URL + HELLO_PATH)
    except Exception as e:
        logger.debug("Extension is not running, returned with error %s", e)
        return False
    return True


def flush_extension():
    try:
        requests.post(AGENT_URL + FLUSH_PATH, data={})
    except Exception as e:
        logger.debug("Failed to flush extension, returned with error %s", e)
        return False
    return True


should_use_extension = is_extension_running()
