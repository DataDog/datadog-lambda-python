# datadog-lambda-python

![build](https://github.com/DataDog/datadog-lambda-python/workflows/build/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/datadog-lambda)](https://pypi.org/project/datadog-lambda/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/datadog-lambda)
[![Slack](https://chat.datadoghq.com/badge.svg?bg=632CA6)](https://chat.datadoghq.com/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/DataDog/datadog-lambda-python/blob/main/LICENSE)

Datadog Lambda Library for Python (3.7, 3.8, 3.9, 3.10, and 3.11) enables [enhanced Lambda metrics](https://docs.datadoghq.com/serverless/enhanced_lambda_metrics), [distributed tracing](https://docs.datadoghq.com/serverless/distributed_tracing), and [custom metric submission](https://docs.datadoghq.com/serverless/custom_metrics) from AWS Lambda functions.

## Installation

Follow the [installation instructions](https://docs.datadoghq.com/serverless/installation/python/), and view your function's enhanced metrics, traces and logs in Datadog.

## Configuration

Follow the [configuration instructions](https://docs.datadoghq.com/serverless/configuration) to tag your telemetry, capture request/response payloads, filter or scrub sensitive information from logs or traces, and more.

Besides the environment variables supported by dd-trace-py, the datadog-lambda-python library added following environment variables.

| Environment Variables | Default ValueDescription |
| -------------------- | ------------ |
| DD_ENCODE_AUTHORIZER_CONTEXT      | When set to `true` for Lambda authorizers, the tracing context will be encoded into the response for propagation. Supported for NodeJS and Python. Defaults to `true`. |
| DD_DECODE_AUTHORIZER_CONTEXT      | When set to `true` for Lambdas that are authorized via Lambda authorizers, it will parse and use the encoded tracing context (if found). Supportedoo for NodeJS and Python. Defaults to `true`. |
| DD_COLD_START_TRACING | Set to `false` to disable Cold Start Tracing. Used in NodeJS and Python. Defaults to `true`. |
| DD_MIN_COLD_START_DURATION |  Sets the minimum duration (in milliseconds) for a module load event to be traced via Cold Start Tracing. Number. Defaults to `3`. |
| DD_COLD_START_TRACE_SKIP_LIB | optionally skip creating Cold Start Spans for a comma-separated list of libraries. Useful to limit depth or skip known libraries. Default depends on runtime. |
| DD_CAPTURE_LAMBDA_PAYLOAD | [Captures incoming and outgoing AWS Lambda payloads][1] in the Datadog APM spans for Lambda invocations. Defaults to `false`. |
| DD_CAPTURE_LAMBDA_PAYLOAD_MAX_DEPTH | The captured AWS Lambda payloads will become tags of the `aws.lambda` span. This sets how deep it fathoms the JSON structure. When the max depth reached, the tag's value will be the stringified value of the deeper nested items. Defaults to `10`. <br> For example, with input payload as <pre>{<br>  "lv1" : {<br>    "lv2": {<br>      "lv3": "val"<br>    }<br>  }<br>}</pre> When set to `2`, the resulted tag's key is `function.request.lv1.lv2` and value `{\"lv3\": \"val\"}`. <br> When set to `0`, the the resulted tag's key is just `function.request` and value is `{\"lv1\":{\"lv2\":{\"lv3\": \"val\"}}}` |


## Opening Issues

If you encounter a bug with this package, we want to hear about it. Before opening a new issue, search the existing issues to avoid duplicates.

When opening an issue, include the Datadog Lambda Library version, Python version, and stack trace if available. In addition, include the steps to reproduce when appropriate.

You can also open an issue for a feature request.

## Lambda Profiling Beta

Datadog's [Continuous Profiler](https://www.datadoghq.com/product/code-profiling/) is now available in beta for Python in version 4.62.0 and layer version 62 and above. This optional feature is enabled by setting the `DD_PROFILING_ENABLED` environment variable to `true`. During the beta period, profiling is available at no additional cost.

The Continuous Profiler works by spawning a thread which periodically wakes up and takes a snapshot of the CPU and Heap of all running python code. This can include the profiler itself. If you want the Profiler to ignore itself, set `DD_PROFILING_IGNORE_PROFILER` to `true`.

## Major Version Notes

### 4.x / Layer version 61+

- Python3.6 support has been [deprecated](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html) by AWS, and support removed from this library.
- `dd-trace` upgraded from 0.61 to 1.4, full release notes are available [here](https://ddtrace.readthedocs.io/en/stable/release_notes.html#v1-0-0)
  - `get_correlation_ids()` has been changed to `get_log_correlation_context()`, which now returns a dictionary containing the active `span_id`, `trace_id`, as well as `service` and `env`.

## Contributing

If you find an issue with this package and have a fix, please feel free to open a pull request following the [procedures](CONTRIBUTING.md).

## Community

For product feedback and questions, join the `#serverless` channel in the [Datadog community on Slack](https://chat.datadoghq.com/).

## License

Unless explicitly stated otherwise all files in this repository are licensed under the Apache License Version 2.0.

This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2019 Datadog, Inc.

[1]: https://www.datadoghq.com/blog/troubleshoot-lambda-function-request-response-payloads/
