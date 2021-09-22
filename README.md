# datadog-lambda-python

![build](https://github.com/DataDog/datadog-lambda-python/workflows/build/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/datadog-lambda)](https://pypi.org/project/datadog-lambda/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/datadog-lambda)
[![Slack](https://chat.datadoghq.com/badge.svg?bg=632CA6)](https://chat.datadoghq.com/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/DataDog/datadog-lambda-python/blob/main/LICENSE)

Datadog Lambda Library for Python (2.7, 3.6, 3.7, 3.8, and 3.9) enables enhanced Lambda metrics, distributed tracing, and custom metric submission from AWS Lambda functions.  

**IMPORTANT NOTE:** AWS Lambda is expected to receive a [breaking change](https://aws.amazon.com/blogs/compute/upcoming-changes-to-the-python-sdk-in-aws-lambda/) on **December 1, 2021**. If you are using Datadog Python Lambda layer version 7 or below, please upgrade to the latest.

## Installation

Follow the [installation instructions](https://docs.datadoghq.com/serverless/installation/python/), and view your function's enhanced metrics, traces and logs in Datadog.

## Custom Metrics

Once [installed](#installation), you should be able to submit custom metrics from your Lambda function.

Check out the instructions for [submitting custom metrics from AWS Lambda functions](https://docs.datadoghq.com/integrations/amazon_lambda/?tab=python#custom-metrics).

## Tracing

Once [installed](#installation), you should be able to view your function's traces in Datadog, and your function's logs should be automatically connected to the traces.

For additional details on trace collection, take a look at [collecting traces from AWS Lambda functions](https://docs.datadoghq.com/integrations/amazon_lambda/?tab=python#trace-collection). 

For additional details on trace and log connection, see [connecting logs and traces](https://docs.datadoghq.com/tracing/connect_logs_and_traces/python/).

For additional details on the tracer, check out the [official documentation for Datadog trace client](http://pypi.datadoghq.com/trace/docs/index.html).

## Enhanced Metrics

Once [installed](#installation), you should be able to view enhanced metrics for your Lambda function in Datadog.

Check out the official documentation on [Datadog Lambda enhanced metrics](https://docs.datadoghq.com/integrations/amazon_lambda/?tab=python#real-time-enhanced-lambda-metrics).

## Environment Variables

### DD_FLUSH_TO_LOG

Set to `true` (recommended) to send custom metrics asynchronously (with no added latency to your Lambda function executions) through CloudWatch Logs with the help of [Datadog Forwarder](https://github.com/DataDog/datadog-serverless-functions/tree/main/aws/logs_monitoring). Defaults to `false`. If set to `false`, you also need to set `DD_API_KEY` and `DD_SITE`.

### DD_API_KEY

If `DD_FLUSH_TO_LOG` is set to `false` (not recommended), the Datadog API Key must be defined by setting one of the following environment variables:

- DD_API_KEY - the Datadog API Key in plain-text, NOT recommended
- DD_KMS_API_KEY - the KMS-encrypted API Key, requires the `kms:Decrypt` permission
- DD_API_KEY_SECRET_ARN - the Secret ARN to fetch API Key from the Secrets Manager, requires the `secretsmanager:GetSecretValue` permission (and `kms:Decrypt` if using a customer managed CMK)
- DD_API_KEY_SSM_NAME - the Parameter Name to fetch API Key from the Systems Manager Parameter Store, requires the `ssm:GetParameter` permission (and `kms:Decrypt` if using a SecureString with a customer managed CMK)

You can also supply or override the API key at runtime (not recommended):

```python
# Override DD API Key after importing datadog_lambda packages
from datadog import api
api._api_key = "MY_API_KEY"
```

### DD_SITE

If `DD_FLUSH_TO_LOG` is set to `false` (not recommended), you must set `DD_SITE`. Possible values are `datadoghq.com`, `datadoghq.eu`, `us3.datadoghq.com` and `ddog-gov.com`. The default is `datadoghq.com`.

### DD_LOGS_INJECTION

Inject Datadog trace id into logs for [correlation](https://docs.datadoghq.com/tracing/connect_logs_and_traces/python/) if you are using a `logging.Formatter` in the default `LambdaLoggerHandler` by the Lambda runtime. Defaults to `true`.

### DD_LOG_LEVEL

Set to `debug` enable debug logs from the Datadog Lambda Library. Defaults to `info`.

### DD_ENHANCED_METRICS

Generate enhanced Datadog Lambda integration metrics, such as, `aws.lambda.enhanced.invocations` and `aws.lambda.enhanced.errors`. Defaults to `true`.

### DD_LAMBDA_HANDLER

Your original Lambda handler.

### DD_TRACE_ENABLED

Initialize the Datadog tracer when set to `true`. Defaults to `false`.

### DD_MERGE_XRAY_TRACES

Set to `true` to merge the X-Ray trace and the Datadog trace, when using both the X-Ray and Datadog tracing. Defaults to `false`.

### DD_INFERRED_SPANS (experimental)

Inferred Spans are spans that Datadog can create based on incoming event metadata. 
Set `DD_INFERRED_SPANS` to `true` to infer spans based on Lambda events.
Inferring upstream spans is only supported if you are using the [Datadog Lambda Extension](https://docs.datadoghq.com/serverless/libraries_integrations/extension/). 
Defaults to `false`.
Infers spans for:
- API Gateway REST events
- API Gateway websocket events
- HTTP API events

## Opening Issues

If you encounter a bug with this package, we want to hear about it. Before opening a new issue, search the existing issues to avoid duplicates.

When opening an issue, include the Datadog Lambda Library version, Python version, and stack trace if available. In addition, include the steps to reproduce when appropriate.

You can also open an issue for a feature request.

## Contributing

If you find an issue with this package and have a fix, please feel free to open a pull request following the [procedures](CONTRIBUTING.md).

## Community

For product feedback and questions, join the `#serverless` channel in the [Datadog community on Slack](https://chat.datadoghq.com/).

## License

Unless explicitly stated otherwise all files in this repository are licensed under the Apache License Version 2.0.

This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2019 Datadog, Inc.
