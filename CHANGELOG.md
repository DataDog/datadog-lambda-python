# CHANGELOG

# Version 12 / 2020-02-03

- Defaults the DD_ENHANCED_METRICS option to `true`
- If DD_ENHANCED_METRICS is enabled, always writes enhanced metrics to stdout
- Breaking change: if you previously set the env var DD_ENHANCED_METRICS=true and did not set DD_FLUSH_TO_LOG=true, the enhanced metrics will no longer be submitted to Datadog synchronously; the metrics will now be written to logs. If you already have a Datadog Forwarder Lambda configured, that will read the enhanced metrics logs and submit the metrics asynchronously. If you do not have a Datadog Forwarder set up, you'll need to create one to get enhanced metrics into your Datadog account. See [Datadog Forwarder Lambda setup instructions](https://github.com/DataDog/datadog-serverless-functions/tree/master/aws/logs_monitoring).
- Because of the breaking change above, we've bumped the major package version so that this release is version 1.12.0. We've set the minor version to 12 so that the minor version of our package stays in alignment with the version of the layer we're releasing.

# Version 11 / 2019-12-06

- Add python 3.8 support
- Upgrade dependencies

# Version 10 / 2019-11-19

- Support fetching API Key from secrets manager using `DD_API_KEY_SECRET_ARN`
- Remove botocore to reduce package size
- Update dependencies

# Version 9 / 2019-11-04

- Tag layer-generated `aws.lambda.enhanced.invocations` and `aws.lambda.enhanced.errors` enhanced metrics with `runtime` and `memorysize`

# Version 8 / 2019-10-24

- Remove vendored botocore requests patching since the package has been removed from the latest botocore
- Update README for enhanced metrics instructions

# Version: 7 / 2019-10-24

- Increment `aws.lambda.enhanced.invocations` and `aws.lambda.enhanced.errors` metrics for each invocation if `DD_ENHANCED_METRICS` env var is set to true.

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
