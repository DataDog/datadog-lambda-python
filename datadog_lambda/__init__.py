import sys


# The requests package is no longer included in the lambda layer, instead use
# the vendored version of requests included in the pip package.  Appending to
# sys.path will make the vendered requests package discoverable.
for i in range(len(sys.path)):
    path = sys.path[i]
    sys.path.append(f"{path}/pip/_vendor")

from datadog_lambda.cold_start import initialize_cold_start_tracing
import os


if os.environ.get("DD_INSTRUMENTATION_TELEMETRY_ENABLED") is None:
    os.environ["DD_INSTRUMENTATION_TELEMETRY_ENABLED"] = "false"

if os.environ.get("DD_API_SECURITY_ENABLED") is None:
    os.environ["DD_API_SECURITY_ENABLED"] = "False"

initialize_cold_start_tracing()

# The minor version corresponds to the Lambda layer version.
# E.g.,, version 0.5.0 gets packaged into layer version 5.
from datadog_lambda.version import __version__  # noqa: E402 F401
from datadog_lambda.logger import initialize_logging  # noqa: E402


initialize_logging(__name__)
