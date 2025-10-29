import datadog_lambda.config  # noqa: F401 needs to be imported before `ddtrace`
from datadog_lambda.cold_start import initialize_cold_start_tracing


initialize_cold_start_tracing()

# The minor version corresponds to the Lambda layer version.
# E.g.,, version 0.5.0 gets packaged into layer version 5.
from datadog_lambda.version import __version__  # noqa: E402 F401
from datadog_lambda.logger import initialize_logging  # noqa: E402


initialize_logging(__name__)


from datadog_lambda.patch import patch_all  # noqa: E402

# Patch third-party libraries for tracing, must be done before importing any
# handler code.
patch_all()
