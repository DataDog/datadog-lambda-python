# datadog-lambda-layer-python

Datadog Lambda Layer for Python (2.7, 3.6 and 3.7) enables custom metric submission from AWS Lambda functions, and distributed tracing between serverful and serverless environments.

## Installation

Datadog Lambda Layer can be added to a Lambda function via AWS Lambda console, [AWS CLI](https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html#configuration-layers-using) or [Serverless Framework](https://serverless.com/framework/docs/providers/aws/guide/layers/#using-your-layers) using the following ARN.

```
arn:aws:lambda:<AWS_REGION>:464622532012:layer:Datadog-Python37:<VERSION>
```

Replace `<AWS_REGION>` with the region where your Lambda function lives, and `<VERSION>` with the desired (or the latest) version that can be found from [CHANGELOG](CHANGELOG.md).

The Datadog API must be defined as an environment variable via [AWS CLI](https://docs.aws.amazon.com/lambda/latest/dg/env_variables.html) or [Serverless Framework](https://serverless-stack.com/chapters/serverless-environment-variables.html):

* DD_API_KEY or DD_KMS_API_KEY (if encrypted by KMS)

Set the following Datadog environment variable to `datadoghq.eu` to send your data to the Datadog EU site.

* DD_SITE

If your Lambda function powers a performance-critical task (e.g., a consumer-facing API). You can avoid the added latencies of metric-submitting API calls, by setting the following Datadog environment variable to `True`. Custom metrics will be submitted asynchronously through CloudWatch Logs and [the Datadog log forwarder](https://github.com/DataDog/datadog-serverless-functions/tree/master/aws/logs_monitoring).

* DD_FLUSH_TO_LOG

### The Serverless Framework

If your Lambda function is deployed using the Serverless Framework, refer to this sample `serverless.yml`.

```yaml
provider:
  name: aws
  runtime: python3.7
  tracing:
    lambda: true
    apiGateway: true

functions:
  hello:
    handler: handler.hello
    events:
      - http:
          path: hello
          method: get
    layers:
      - arn:aws:lambda:us-east-1:464622532012:layer:Datadog-Python37:1
    environment:
      DATADOG_API_KEY: xxx
```


## Basic Usage

```python
import requests
from datadog_lambda.wrapper import datadog_lambda_wrapper
from datadog_lambda.metric import lambda_metric

@datadog_lambda_wrapper
def lambda_handler(event, context):
    lambda_metric("my_metric", 10, tags=['tag:value'])
    requests.get("https://www.datadoghq.com")
```


## Custom Metrics

Custom metrics can be submitted using `lambda_metric` and the Lambda handler function needs to be decorated with `@datadog_lambda_wrapper`. The metrics are submitted as [distribution metrics](https://docs.datadoghq.com/graphing/metrics/distributions/).

```python
from datadog_lambda.metric import lambda_metric

@datadog_lambda_wrapper
def lambda_handler(event, context):
    lambda_metric(
        "coffee_house.order_value",  # metric
        12.45,  # value
        tags=['product:latte', 'order:online']  # tags
    )
```

### VPC
If your Lambda function is associated with a VPC, you need to ensure it has [access to the public internet](https://aws.amazon.com/premiumsupport/knowledge-center/internet-access-lambda-function/).


## Distributed Tracing

[Distributed tracing](https://docs.datadoghq.com/tracing/guide/distributed_tracing/?tab=python) allows you to propagate a  trace context from a service running on a host to a service running on AWS Lambda, and vice versa, so you can see performance end-to-end. Linking is implemented by injecting Datadog trace context into the HTTP request headers.

Distributed tracing headers are language agnostic, e.g., a  trace can be propagated between a Java service running on a host to a Lambda function written in Python.

Because the trace context is propagated through HTTP request headers, the Lambda function needs to be triggered by AWS API Gateway or AWS Application Load Balancer.

To enable this feature, you simple need to decorate your Lambda handler function with `@datadog_lambda_wrapper`.

```python
import requests
from datadog_lambda.wrapper import datadog_lambda_wrapper

@datadog_lambda_wrapper
def lambda_handler(event, context):
    requests.get("https://www.datadoghq.com")
```

Note, the Datadog Lambda Layer is only needed to enable *distributed* tracing between Lambda and non-Lambda services. For standalone Lambda functions, traces can be found in Datadog APM after configuring [the X-Ray integration](https://docs.datadoghq.com/integrations/amazon_xray/).

### Patching

By default, widely used HTTP client libraries, such as `requests`, `urllib2` and `urllib.request` are patched automatically to inject Datadog trace context into outgoing requests.

You can also manually retrieve the Datadog trace context (i.e., http headers in a Python dict) and inject it to request headers when needed.

```python
import requests
from datadog_lambda.wrapper import datadog_lambda_wrapper
from datadog_lambda.tracing import get_dd_trace_context

@datadog_lambda_wrapper
def lambda_handler(event, context):
    headers = get_dd_trace_context()
    requests.get("https://www.datadoghq.com", headers=headers)
```

### Sampling

The traces for your Lambda function are converted by Datadog from AWS X-Ray traces. X-Ray needs to sample the traces that the Datadog tracing agent decides to sample, in order to collect as many complete traces as possible. You can create X-Ray sampling rules to ensure requests with header `x-datadog-sampling-priority:1` or `x-datadog-sampling-priority:2` via API Gateway always get sampled by X-Ray.

These rules can be created using the following AWS CLI command.

```bash
aws xray create-sampling-rule --cli-input-json file://datadog-sampling-priority-1.json
aws xray create-sampling-rule --cli-input-json file://datadog-sampling-priority-2.json
```

The file content for `datadog-sampling-priority-1.json`:
```json
{
    "SamplingRule": {
        "RuleName": "Datadog-Sampling-Priority-1",
        "ResourceARN": "*",
        "Priority": 9998,
        "FixedRate": 1,
        "ReservoirSize": 100,
        "ServiceName": "*",
        "ServiceType": "AWS::APIGateway::Stage",
        "Host": "*",
        "HTTPMethod": "*",
        "URLPath": "*",
        "Version": 1,
        "Attributes": {
            "x-datadog-sampling-priority": "1"
        }
    }
}
```

The file content for `datadog-sampling-priority-2.json`:
```json
{
    "SamplingRule": {
        "RuleName": "Datadog-Sampling-Priority-2",
        "ResourceARN": "*",
        "Priority": 9999,
        "FixedRate": 1,
        "ReservoirSize": 100,
        "ServiceName": "*",
        "ServiceType": "AWS::APIGateway::Stage",
        "Host": "*",
        "HTTPMethod": "*",
        "URLPath": "*",
        "Version": 1,
        "Attributes": {
            "x-datadog-sampling-priority": "2"
        }
    }
}
```

### Non-proxy integration

If your Lambda function is triggered by API Gateway via [the non-proxy integration](https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-lambda-non-proxy-integration.html), then you have to [set up a mapping template](https://aws.amazon.com/premiumsupport/knowledge-center/custom-headers-api-gateway-lambda/), which passes the Datadog trace context from the incoming HTTP request headers to the Lambda function via the `event` object.

If your Lambda function is deployed by the Serverless Framework, such a mapping template gets created by default.


## Opening Issues

If you encounter a bug with this package, we want to hear about it. Before opening a new issue, search the existing issues to avoid duplicates.

When opening an issue, include the Datadog Lambda Layer version, Python version, and stack trace if available. In addition, include the steps to reproduce when appropriate.

You can also open an issue for a feature request.


## Contributing

If you find an issue with this package and have a fix, please feel free to open a pull request following the [procedures](CONTRIBUTING.md).


## License

Unless explicitly stated otherwise all files in this repository are licensed under the Apache License Version 2.0.

This product includes software developed at Datadog (https://www.datadoghq.com/). Copyright 2019 Datadog, Inc.
