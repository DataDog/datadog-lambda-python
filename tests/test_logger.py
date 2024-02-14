import io
import logging
import pytest

from datadog_lambda.logger import initialize_logging

_test_initialize_logging = (
    ("TRACE", (10, 20, 30, 40, 50)),
    ("DEBUG", (10, 20, 30, 40, 50)),
    ("debug", (10, 20, 30, 40, 50)),
    ("INFO", (20, 30, 40, 50)),
    ("WARNING", (30, 40, 50)),
    ("WARN", (30, 40, 50)),
    ("ERROR", (40, 50)),
    ("CRITICAL", (50,)),
    ("OFF", ()),
    ("", (20, 30, 40, 50)),
    (None, (20, 30, 40, 50)),
    ("PURPLE", (30, 20, 30, 40, 50)),  # log warning then default to INFO
)


@pytest.mark.parametrize("level,logged_levels", _test_initialize_logging)
def test_initialize_logging(level, logged_levels, monkeypatch):
    if level is not None:
        monkeypatch.setenv("DD_LOG_LEVEL", level)

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelno)s"))
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)

    initialize_logging(__name__)

    logger.debug("debug")
    logger.info("info")
    logger.warning("warning")
    logger.error("error")
    logger.critical("critical")

    logged = tuple(map(int, stream.getvalue().strip().split()))
    assert logged == logged_levels
