import logging
import os

try:
    _level_mappping = logging.getLevelNamesMapping()
except AttributeError:
    # python 3.8
    _level_mappping = {name: num for num, name in logging._levelToName.items()}
# https://docs.datadoghq.com/agent/troubleshooting/debug_mode/?tab=agentv6v7#agent-log-level
_level_mappping.update(
    {
        "TRACE": 5,
        "WARN": logging.WARNING,
        "OFF": 100,
    }
)


def initialize_logging(name):
    logger = logging.getLogger(name)
    str_level = (os.environ.get("DD_LOG_LEVEL") or "INFO").upper()
    level = _level_mappping.get(str_level)
    if level is None:
        logger.setLevel(logging.INFO)
        logger.warning("Invalid log level: %s Defaulting to INFO", str_level)
    else:
        logger.setLevel(level)
