import logging
from os import path

try:
    # only available in python 3
    # not an issue since the extension is not compatible with python 2.x runtime
    # https://docs.aws.amazon.com/lambda/latest/dg/using-extensions.html
    import urllib.request
except ImportError:
    # safe since both calls to urllib are protected with try/expect and will return false
    urllib = None

AGENT_URL = "http://127.0.0.1:8124"
HELLO_PATH = "/lambda/hello"
FLUSH_PATH = "/lambda/flush"
EXTENSION_PATH = "/opt/extensions/datadog-agent"

logger = logging.getLogger(__name__)


def is_extension_running():
    if not path.exists(EXTENSION_PATH):
        return False
    try:
        urllib.request.urlopen(AGENT_URL + HELLO_PATH)
    except Exception as e:
        logger.debug("Extension is not running, returned with error %s", e)
        return False
    return True


def flush_extension():
    try:
        req = urllib.request.Request(AGENT_URL + FLUSH_PATH, "".encode("ascii"))
        urllib.request.urlopen(req)
    except Exception as e:
        logger.debug("Failed to flush extension, returned with error %s", e)
        return False
    return True


should_use_extension = is_extension_running()
