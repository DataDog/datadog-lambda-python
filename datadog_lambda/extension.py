import logging
import requests

AGENT_URL = "http://127.0.0.1:8124"
HELLO_PATH = "/lambda/hello"
FLUSH_PATH = "/lambda/flush"

logger = logging.getLogger(__name__)


def is_extension_running():
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


use_extension = is_extension_running()
