# datadog-lambda-python

![build](https://github.com/DataDog/datadog-lambda-python/workflows/build/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/datadog-lambda)](https://pypi.org/project/datadog-lambda/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/datadog-lambda)
[![Slack](https://chat.datadoghq.com/badge.svg?bg=632CA6)](https://chat.datadoghq.com/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/DataDog/datadog-lambda-python/blob/main/LICENSE)

Datadog Lambda Library for Python (3.6, 3.7, 3.8, and 3.9) enables [enhanced Lambda metrics](https://docs.datadoghq.com/serverless/enhanced_lambda_metrics), [distributed tracing](https://docs.datadoghq.com/serverless/distributed_tracing), and [custom metric submission](https://docs.datadoghq.com/serverless/custom_metrics) from AWS Lambda functions.

## Installation

Follow the [installation instructions](https://docs.datadoghq.com/serverless/installation/python/), and view your function's enhanced metrics, traces and logs in Datadog.

For advanced distributed tracing use cases, check out the [official documentation for Datadog APM client](https://ddtrace.readthedocs.io).

To connect traces and logs using a custom logger, see [connecting logs and traces](https://docs.datadoghq.com/tracing/connect_logs_and_traces/python/).

## Environment Variables

### DD_API_KEY

If you are using the [Datadog Lambda Extension](https://docs.datadoghq.com/serverless/libraries_integrations/extension/), the Datadog API Key must be defined by setting one of the following environment variables:

- DD_API_KEY - the Datadog API Key in plain-text, NOT recommended
- DD_KMS_API_KEY - the KMS-encrypted API Key, requires the `kms:Decrypt` permission
- DD_API_KEY_SECRET_ARN - the Secret ARN to fetch API Key from the Secrets Manager, requires the `secretsmanager:GetSecretValue` permission (and `kms:Decrypt` if using a customer managed CMK)

If you are using the [Datadog Forwarder](https://github.com/DataDog/datadog-serverless-functions/tree/main/aws/logs_monitoring), you must set the Datadog API Key on the Datadog Forwarder instead of your own Lambda function.

### DD_SITE

If you are using the [Datadog Lambda Extension](https://docs.datadoghq.com/serverless/libraries_integrations/extension/), you must set `DD_SITE` on your Lambda function based on your [Datadog site](https://docs.datadoghq.com/getting_started/site/). The default is `datadoghq.com`. 

If you are using the [Datadog Forwarder](https://github.com/DataDog/datadog-serverless-functions/tree/main/aws/logs_monitoring), you must set this on the Datadog Forwarder instead of your own Lambda function.

### DD_LOGS_INJECTION

Inject Datadog trace id into logs for [correlation](https://docs.datadoghq.com/tracing/connect_logs_and_traces/python/) if you are using a `logging.Formatter` in the default `LambdaLoggerHandler` by the Lambda runtime. Defaults to `true`.

### DD_LOG_LEVEL

Set to `debug` enable debug logs from the Datadog Lambda Library. Defaults to `info`.

### DD_ENHANCED_METRICS

Generate enhanced Datadog Lambda integration metrics, such as, `aws.lambda.enhanced.invocations` and `aws.lambda.enhanced.errors`. Defaults to `true`.

### DD_LAMBDA_HANDLER

In order to instrument individual invocations, the Datadog Lambda library needs to wrap around your Lambda handler function. This is usually achieved by setting your function's handler to the Datadog handler function (`datadog_lambda.handler.handler`) and setting the environment variable `DD_LAMBDA_HANDLER` with your original handler function to be called by the Datadog handler.

For some advanced use cases, instead of overriding the handler setting and the `DD_LAMBDA_HANDLER` environment variable, you can apply the Datadog Lambda library wrapper in your function code like below:

```python
from datadog_lambda.wrapper import datadog_lambda_wrapper

@datadog_lambda_wrapper
def my_lambda_handle(event, context):
    # your function code
```

### DD_TRACE_ENABLED

Initialize the Datadog tracer when set to `true`. Defaults to `false`.

### DD_MERGE_XRAY_TRACES

Set to `true` to merge the X-Ray trace and the Datadog trace, when using both the X-Ray and Datadog tracing. Defaults to `false`.

### DD_TRACE_MANAGED_SERVICES (experimental)

Inferred Spans are spans that Datadog can create based on incoming event metadata.
Set `DD_TRACE_MANAGED_SERVICES` to `true` to infer spans based on Lambda events.
Inferring upstream spans is only supported if you are using the [Datadog Lambda Extension](https://docs.datadoghq.com/serverless/libraries_integrations/extension/).
Defaults to `true`.
Infers spans for:

- API Gateway REST events
- API Gateway WebSocket events
- HTTP API events
- SQS
- SNS (SNS messaged delivered via SQS are also supported)
- Kinesis Streams (if data is a JSON string or base64 encoded JSON string)
- EventBridge (custom events, where Details is a JSON string)
- S3
- DynamoDB

### DD_FLUSH_TO_LOG (Deprecated)

When the [Datadog Forwarder](https://github.com/DataDog/datadog-serverless-functions/tree/main/aws/logs_monitoring) was launched previously, `DD_FLUSH_TO_LOG` was introduced to control whether to send custom metrics synchronously from your own Lambda function directly to Datadog with added latency (set `DD_FLUSH_TO_LOG` to `false` and you also need to set `DD_API_KEY` and `DD_SITE`) or asynchronously through CloudWatch logs (set `DD_FLUSH_TO_LOG` to `true`).

Now you should consider adopting the [Datadog Lambda Extension](https://docs.datadoghq.com/serverless/libraries_integrations/extension/) for sending custom metrics. When the Datadog Lambda Extension is installed and detected, `DD_FLUSH_TO_LOG` is ignored. If you wish to Defaults to `false`. If set to `false`, you also need to set `DD_API_KEY` and `DD_SITE`.

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
