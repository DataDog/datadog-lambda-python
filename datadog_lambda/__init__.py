# The minor version corresponds to the Lambda layer version.
# E.g.,, version 0.5.0 gets packaged into layer version 5.
__version__ = "3.47.0"


import os
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.getLevelName(os.environ.get("DD_LOG_LEVEL", "INFO").upper()))
