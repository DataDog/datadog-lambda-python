import logging
from os import path

HELLO_PATH = "/lambda/hello"
FLUSH_PATH = "/lambda/flush"
EXTENSION_PATH = "/opt/extensions/datadog-agent"

logger = logging.getLogger(__name__)


try:
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", 8124)
except Exception as e:
    logger.debug("unable to create http connection to extension: ", e)
    conn = None


def is_extension_running():
    if not path.exists(EXTENSION_PATH):
        return False
    try:
        conn.request("GET", HELLO_PATH)
        resp = conn.getresponse()
        return resp.status == 200
    except Exception as e:
        logger.debug("Extension is not running, returned with error %s", e)
        return False
    return True


def flush_extension():
    try:
        conn.request("POST", FLUSH_PATH, b"")
        resp = conn.getresponse()
        return resp.status == 200
    except Exception as e:
        logger.debug("Failed to flush extension, returned with error %s", e)
        return False
    return True


should_use_extension = is_extension_running()
