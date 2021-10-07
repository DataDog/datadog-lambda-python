# The minor version corresponds to the Lambda layer version.
# E.g.,, version 0.5.0 gets packaged into layer version 5.
# try:
#     import importlib.metadata as importlib_metadata
# except ModuleNotFoundError:
#     import importlib_metadata

# __version__ = importlib_metadata.version(__name__)
__version__ = "3.49.0"


import os
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.getLevelName(os.environ.get("DD_LOG_LEVEL", "INFO").upper()))
