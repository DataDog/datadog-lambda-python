# CHANGELOG

# Version: 6 / 2019-09-16

- Support `DD_LOGS_INJECTION` for trace and log correlation

# Version: 5 / 2019-07-26

- Publish the layer as a package `datadog_lambda` to PyPI
- Support environment variable `DD_LOG_LEVEL` for debugging

# Version: 4 / 2019-07-23

- Correctly parse trace headers with mixed casing

# Version: 3 / 2019-06-18

- Log metrics in a compact format

# Version: 2 / 2019-06-10

- Support submitting metrics through CloudWatch Logs
- Support submitting metrics to `datadoghq.eu`
- Support KMS-encrypted DD API Key
- Fix a few bugs

# Version: 1 / 2019-05-06

- First release
- Support submitting distribution metrics from Lambda functions
- Support distributed tracing between serverful and serverless services
