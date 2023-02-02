# The minor version corresponds to the Lambda layer version.
# E.g.,, version 0.5.0 gets packaged into layer version 5.
try:
    import importlib.metadata as importlib_metadata
except ModuleNotFoundError:
    import importlib_metadata

__version__ = importlib_metadata.version(__name__)
import sys
print(f"__INIT__BEFORE_INSTALL {sys.meta_path}")
from datadog_lambda.module import ModuleWatchdog
ModuleWatchdog.install()
print(f"__INIT__AFTER_INSTALL {sys.meta_path}")

import os
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.getLevelName(os.environ.get("DD_LOG_LEVEL", "INFO").upper()))
