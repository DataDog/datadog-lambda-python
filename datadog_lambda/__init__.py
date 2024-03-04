from datadog_lambda.cold_start import initialize_cold_start_tracing
from datadog_lambda.logger import initialize_logging
import os


if os.environ.get("DD_INSTRUMENTATION_TELEMETRY_ENABLED") is None:
    os.environ["DD_INSTRUMENTATION_TELEMETRY_ENABLED"] = "false"

if os.environ.get("DD_API_SECURITY_ENABLED") is None:
    os.environ["DD_API_SECURITY_ENABLED"] = "False"

initialize_cold_start_tracing()

# The minor version corresponds to the Lambda layer version.
# E.g.,, version 0.5.0 gets packaged into layer version 5.
try:
    import importlib.metadata as importlib_metadata
except ModuleNotFoundError:
    import importlib_metadata

__version__ = importlib_metadata.version(__name__)

initialize_logging(__name__)
