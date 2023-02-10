from datadog_lambda.cold_start import is_cold_start, wrap_find_spec

if is_cold_start():
    import os

    if (
        os.environ.get("DD_TRACE_ENABLED", "true").lower() == "true"
        and os.environ.get("DD_COLD_START_TRACING", "true").lower() == "true"
    ):
        from sys import version_info, meta_path

        if version_info >= (3, 7):  # current implementation only support version > 3.7
            for importer in meta_path:
                try:
                    importer.find_spec = wrap_find_spec(importer.find_spec)
                except:
                    pass

# The minor version corresponds to the Lambda layer version.
# E.g.,, version 0.5.0 gets packaged into layer version 5.
try:
    import importlib.metadata as importlib_metadata
except ModuleNotFoundError:
    import importlib_metadata

__version__ = importlib_metadata.version(__name__)

import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.getLevelName(os.environ.get("DD_LOG_LEVEL", "INFO").upper()))
