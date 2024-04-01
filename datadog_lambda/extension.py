import logging
import os

AGENT_URL = "http://127.0.0.1:8124"
FLUSH_PATH = "/lambda/flush"
EXTENSION_PATH = "/opt/extensions/datadog-agent"

logger = logging.getLogger(__name__)


def is_extension_present():
    return os.path.exists(EXTENSION_PATH)


def flush_extension():
    try:
        import urllib.request

        req = urllib.request.Request(AGENT_URL + FLUSH_PATH, "".encode("ascii"))
        urllib.request.urlopen(req)
    except Exception as e:
        logger.debug("Failed to flush extension, returned with error %s", e)
        return False
    return True


should_use_extension = is_extension_present()
