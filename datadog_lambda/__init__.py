from datadog_lambda.cold_start import initialize_cold_start_tracing
from datadog_lambda.logger import initialize_logging

initialize_cold_start_tracing()

# The minor version corresponds to the Lambda layer version.
# E.g.,, version 0.5.0 gets packaged into layer version 5.
try:
    import importlib.metadata as importlib_metadata
except ModuleNotFoundError:
    import importlib_metadata

__version__ = importlib_metadata.version(__name__)

initialize_logging(__name__)
