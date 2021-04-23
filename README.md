# Instrumenting Python AWS Lambda Applications

![build](https://github.com/DataDog/datadog-lambda-python/workflows/build/badge.svg)
[![PyPI](https://img.shields.io/pypi/v/datadog-lambda)](https://pypi.org/project/datadog-lambda/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/datadog-lambda)
[![Slack](https://chat.datadoghq.com/badge.svg?bg=632CA6)](https://chat.datadoghq.com/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/DataDog/datadog-lambda-python/blob/main/LICENSE)

## Required Setup

If not already configured:

- Install the [AWS integration][1]. This allows Datadog to ingest Lambda metrics from AWS. 
- Install the [Datadog Forwarder Lambda function][2], which is required to ingest AWS Lambda traces, enhanced metrics, custom metrics, and logs. 

After you have installed the [AWS integration][1] and the [Datadog Forwarder][2], follow these steps to instrument your application to send metrics, logs, and traces to Datadog.

## Configuration

<!-- xxx tabs xxx -->
<!-- xxx tab "Serverless Framework" xxx -->

The [Datadog Serverless Plugin][1] automatically adds the Datadog Lambda library to your functions using a layer, and configures your functions to send metrics, traces, and logs to Datadog through the [Datadog Forwarder][2].

If your Lambda function is configured to use code signing, you must add Datadog's Signing Profile ARN (`arn:aws:signer:us-east-1:464622532012:/signing-profiles/DatadogLambdaSigningProfile/9vMI9ZAGLc`) to your function's [Code Signing Configuration][3] before you install the Datadog Serverless Plugin. 

To install and configure the Datadog Serverless Plugin, follow these steps:

1. Install the Datadog Serverless Plugin: 
	  ```
    yarn add --dev serverless-plugin-datadog
    ```
2. In your `serverless.yml`, add the following:
    ```
    plugins:
      - serverless-plugin-datadog
    ```
3. In your `serverless.yml`, also add the following section:
    ```
    custom:
      datadog:
        forwarder: # The Datadog Forwarder ARN goes here.
    ```
    More information on the Datadog Forwarder ARN or installation can be found [here][2]. For additional settings, see the [plugin documentation][1].

[1]: https://docs.datadoghq.com/serverless/serverless_integrations/plugin
[2]: https://docs.datadoghq.com/serverless/forwarder/
[3]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html#config-codesigning-config-update

<!-- xxx tab xxx -->
<!-- xxx tab "AWS SAM" xxx -->

The [Datadog CloudFormation macro][1] automatically transforms your SAM application template to add the Datadog Lambda library to your functions using layers, and configure your functions to send metrics, traces, and logs to Datadog through the [Datadog Forwarder][2].

### Install the Datadog CloudFormation Macro

Run the following command with your [AWS credentials][3] to deploy a CloudFormation stack that installs the macro AWS resource. You only need to install the macro **once** for a given region in your account. Replace `create-stack` with `update-stack` to update the macro to the latest version.

```sh
aws cloudformation create-stack \
  --stack-name datadog-serverless-macro \
  --template-url https://datadog-cloudformation-template.s3.amazonaws.com/aws/serverless-macro/latest.yml \
  --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_IAM
```

The macro is now deployed and ready to use.

### Instrument the Function

In your `template.yml`, add the following under the `Transform` section, **after** the `AWS::Serverless` transform for SAM.

```yaml
Transform:
  - AWS::Serverless-2016-10-31
  - Name: DatadogServerless
    Parameters:
      pythonLayerVersion: "<LAYER_VERSION>"
      stackName: !Ref "AWS::StackName"
      forwarderArn: "<FORWARDER_ARN>"
      service: "<SERVICE>" # Optional
      env: "<ENV>" # Optional
```

Replace `<SERVICE>` and `<ENV>` with appropriate values, `<LAYER_VERSION>` with the desired version of Datadog Lambda layer (see the [latest releases][4]), and `<FORWARDER_ARN>` with Forwarder ARN (see the [Forwarder documentation][2]).

If your Lambda function is configured to use code signing, you must add Datadog's Signing Profile ARN (`arn:aws:signer:us-east-1:464622532012:/signing-profiles/DatadogLambdaSigningProfile/9vMI9ZAGLc`) to your function's [Code Signing Configuration][5] before you can use the macro.

More information and additional parameters can be found in the [macro documentation][1].

[1]: https://docs.datadoghq.com/serverless/serverless_integrations/macro
[2]: https://docs.datadoghq.com/serverless/forwarder/
[3]: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html
[4]: https://github.com/DataDog/datadog-lambda-python/releases
[5]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html#config-codesigning-config-update

<!-- xxx tab xxx -->
<!-- xxx tab "AWS CDK" xxx -->

The [Datadog CloudFormation macro][1] automatically transforms the CloudFormation template generated by the AWS CDK to add the Datadog Lambda library to your functions using layers, and configure your functions to send metrics, traces, and logs to Datadog through the [Datadog Forwarder][2].

### Install the Datadog CloudFormation Macro

Run the following command with your [AWS credentials][3] to deploy a CloudFormation stack that installs the macro AWS resource. You only need to install the macro **once** for a given region in your account. Replace `create-stack` with `update-stack` to update the macro to the latest version.

```sh
aws cloudformation create-stack \
  --stack-name datadog-serverless-macro \
  --template-url https://datadog-cloudformation-template.s3.amazonaws.com/aws/serverless-macro/latest.yml \
  --capabilities CAPABILITY_AUTO_EXPAND CAPABILITY_IAM
```

The macro is now deployed and ready to use.

### Instrument the Function

Add the `DatadogServerless` transform and the `CfnMapping` to your `Stack` object in your AWS CDK app. See the sample code below in Python (the usage in other language should be similar).

```python
from aws_cdk import core

class CdkStack(core.Stack):
  def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
    super().__init__(scope, id, **kwargs)
    self.add_transform("DatadogServerless")

    mapping = core.CfnMapping(self, "Datadog",
      mapping={
        "Parameters": {
          "pythonLayerVersion": "<LAYER_VERSION>",
          "forwarderArn": "<FORWARDER_ARN>",
          "stackName": self.stackName,
          "service": "<SERVICE>",  # Optional
          "env": "<ENV>",  # Optional
        }
      })
```

Replace `<SERVICE>` and `<ENV>` with appropriate values, `<LAYER_VERSION>` with the desired version of Datadog Lambda layer (see the [latest releases][4]), and `<FORWARDER_ARN>` with Forwarder ARN (see the [Forwarder documentation][2]).

If your Lambda function is configured to use code signing, you must add Datadog's Signing Profile ARN (`arn:aws:signer:us-east-1:464622532012:/signing-profiles/DatadogLambdaSigningProfile/9vMI9ZAGLc`) to your function's [Code Signing Configuration][5] before you can use the macro.

More information and additional parameters can be found in the [macro documentation][1].

[1]: https://docs.datadoghq.com/serverless/serverless_integrations/macro
[2]: https://docs.datadoghq.com/serverless/forwarder/
[3]: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html
[4]: https://github.com/DataDog/datadog-lambda-python/releases
[5]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html#config-codesigning-config-update

<!-- xxx tab xxx -->
<!-- xxx tab "Zappa" xxx -->

### Update the Zappa Settings

1. Add the following settings to your `zappa_settings.json`:
    ```json
    {
        "dev": {
            "layers": ["arn:aws:lambda:<AWS_REGION>:464622532012:layer:Datadog-<RUNTIME>:<VERSION>"],
            "lambda_handler": "datadog_lambda.handler.handler",
            "aws_environment_variables": {
                "DD_LAMBDA_HANDLER": "handler.lambda_handler",
                "DD_TRACE_ENABLED": "true",
                "DD_FLUSH_TO_LOG": "true",
            },
        }
    }
    ```
1. Replace the placeholder `<AWS_REGION>`, `<RUNTIME>` and `<VERSION>` in the layer ARN with appropriate values. The available `RUNTIME` options are `Python27`, `Python36`, `Python37`, and `Python38`. For `VERSION`, see the [latest release][1]. For example:
    ```
    # For regular regions
    arn:aws:lambda:us-east-1:464622532012:layer:Datadog-Python37:19
    
    # For us-gov regions
    arn:aws-us-gov:lambda:us-gov-east-1:002406178527:layer:Datadog-Python37:19
    ```
1. If your Lambda function is configured to use code signing, add Datadog's Signing Profile ARN (`arn:aws:signer:us-east-1:464622532012:/signing-profiles/DatadogLambdaSigningProfile/9vMI9ZAGLc`) to your function's [Code Signing Configuration][2]. 

### Subscribe the Datadog Forwarder to the Log Groups

You need to subscribe the Datadog Forwarder Lambda function to each of your function’s log groups, to send metrics, traces, and logs to Datadog.

1. [Install the Datadog Forwarder][3] if you haven't.
2. [Subscribe the Datadog Forwarder to your function's log groups][4].


[1]: https://github.com/DataDog/datadog-lambda-python/releases
[2]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html#config-codesigning-config-update
[3]: https://docs.datadoghq.com/serverless/forwarder/
[4]: https://docs.datadoghq.com/logs/guide/send-aws-services-logs-with-the-datadog-lambda-function/#collecting-logs-from-cloudwatch-log-group

<!-- xxx tab xxx -->
<!-- xxx tab "Datadog CLI" xxx -->

<div class="alert alert-warning">This service is in public beta. If you have any feedback, contact <a href="/help">Datadog support</a>.</div>

Use the Datadog CLI to set up instrumentation on your Lambda functions in your CI/CD pipelines. The CLI command automatically adds the Datadog Lambda library to your functions using layers, and configures your functions to send metrics, traces, and logs to Datadog.

### Install the Datadog CLI

Install the Datadog CLI with NPM or Yarn:

```sh
# NPM
npm install -g @datadog/datadog-ci

# Yarn
yarn global add @datadog/datadog-ci
```

### Instrument the Function

Run the following command with your [AWS credentials][1]. Replace `<functionname>` and `<another_functionname>` with your Lambda function names, `<aws_region>` with the AWS region name, `<layer_version>` with the desired version of the Datadog Lambda layer (see [latest releases][2]) and `<forwarder_arn>` with Forwarder ARN (see the [Forwarder documentation][3]).

```sh
datadog-ci lambda instrument -f <functionname> -f <another_functionname> -r <aws_region> -v <layer_version> --forwarder	<forwarder_arn>
```

For example:

```sh
datadog-ci lambda instrument -f my-function -f another-function -r us-east-1 -v 19 --forwarder arn:aws:lambda:us-east-1:000000000000:function:datadog-forwarder
```

If your Lambda function is configured to use code signing, you must add Datadog's Signing Profile ARN (`arn:aws:signer:us-east-1:464622532012:/signing-profiles/DatadogLambdaSigningProfile/9vMI9ZAGLc`) to your function's [Code Signing Configuration][4] before you can instrument it with the Datadog CLI. 

More information and additional parameters can be found in the [CLI documentation][5].

[1]: https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/setting-credentials-node.html
[2]: https://github.com/DataDog/datadog-lambda-python/releases
[3]: https://docs.datadoghq.com/serverless/forwarder/
[4]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html#config-codesigning-config-update
[5]: https://docs.datadoghq.com/serverless/serverless_integrations/cli

<!-- xxx tab xxx -->
<!-- xxx tab "Container Image" xxx -->

### Install the Datadog Lambda Library

If you are deploying your Lambda function as a container image, you cannot use the Datadog Lambda library as a layer. Instead, you must install the Datadog Lambda library directly within the image.


```sh
pip install datadog-lambda
```

Note that the minor version of the `datadog-lambda` package always matches the layer version. For example, `datadog-lambda v0.5.0` matches the content of layer version 5.

### Configure the Function

1. Set your image's `CMD` value to `datadog_lambda.handler.handler`. You can either set this directly in your Dockerfile or override the value using AWS.
2. Set the environment variable `DD_LAMBDA_HANDLER` to your original handler, for example, `myfunc.handler`.
3. Set the environment variable `DD_TRACE_ENABLED` to `true`.
4. Set the environment variable `DD_FLUSH_TO_LOG` to `true`.
5. Optionally add a `service` and `env` tag with appropriate values to your function.

### Subscribe the Datadog Forwarder to the Log Groups

You need to subscribe the Datadog Forwarder Lambda function to each of your functions' log groups in order to send metrics, traces, and logs to Datadog.

1. [Install the Datadog Forwarder if you haven't][1].
2. [Subscribe the Datadog Forwarder to your function's log groups][2].


[1]: https://docs.datadoghq.com/serverless/forwarder/
[2]: https://docs.datadoghq.com/logs/guide/send-aws-services-logs-with-the-datadog-lambda-function/#collecting-logs-from-cloudwatch-log-group

<!-- xxx tab xxx -->
<!-- xxx tab "Custom" xxx -->

### Install the Datadog Lambda Library

You can either install the Datadog Lambda library as a layer (recommended) or as a Python package.

The minor version of the `datadog-lambda` package always matches the layer version. E.g., datadog-lambda v0.5.0 matches the content of layer version 5.

#### Using the Layer

[Configure the layers][1] for your Lambda function using the ARN in the following format:

```
# For regular regions
arn:aws:lambda:<AWS_REGION>:464622532012:layer:Datadog-<RUNTIME>:<VERSION>

# For us-gov regions
arn:aws-us-gov:lambda:<AWS_REGION>:002406178527:layer:Datadog-<RUNTIME>:<VERSION>
```

The available `RUNTIME` options are `Python27`, `Python36`, `Python37`, and `Python38`. For `VERSION`, see the [latest release][2]. For example:

```
arn:aws:lambda:us-east-1:464622532012:layer:Datadog-Python37:19
```

If your Lambda function is configured to use code signing, you must add Datadog's Signing Profile ARN (`arn:aws:signer:us-east-1:464622532012:/signing-profiles/DatadogLambdaSigningProfile/9vMI9ZAGLc`) to your function's [Code Signing Configuration][3] before you can add the Datadog Lambda library as a layer.

#### Using the Package

Install `datadog-lambda` and its dependencies locally to your function project folder. **Note**: `datadog-lambda` depends on `ddtrace`, which uses native extensions; therefore they must be installed and compiled in a Linux environment. For example, you can use [dockerizePip][4] for the Serverless Framework and [--use-container][5] for AWS SAM. For more details, see [how to add dependencies to your function deployment package][6].

```
pip install datadog-lambda -t ./
```

See the [latest release][7]. 

### Configure the Function

1. Set your function's handler to `datadog_lambda.handler.handler`.
2. Set the environment variable `DD_LAMBDA_HANDLER` to your original handler, for example, `myfunc.handler`.
3. Set the environment variable `DD_TRACE_ENABLED` to `true`.
4. Set the environment variable `DD_FLUSH_TO_LOG` to `true`.
5. Optionally add a `service` and `env` tag with appropriate values to your function.

### Subscribe the Datadog Forwarder to the Log Groups

You need to subscribe the Datadog Forwarder Lambda function to each of your function’s log groups, to send metrics, traces, and logs to Datadog.

1. [Install the Datadog Forwarder][8] if you haven't.
2. [Subscribe the Datadog Forwarder to your function's log groups][9].


[1]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.html
[2]: https://github.com/DataDog/datadog-lambda-python/releases
[3]: https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html#config-codesigning-config-update
[4]: https://github.com/UnitedIncome/serverless-python-requirements#cross-compiling
[5]: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-build.html
[6]: https://docs.aws.amazon.com/lambda/latest/dg/python-package.html#python-package-dependencies
[7]: https://pypi.org/project/datadog-lambda/
[8]: https://docs.datadoghq.com/serverless/forwarder/
[9]: https://docs.datadoghq.com/logs/guide/send-aws-services-logs-with-the-datadog-lambda-function/#collecting-logs-from-cloudwatch-log-group

<!-- xxx tab xxx -->
<!-- xxx tabs xxx -->

### Unified Service Tagging

Although it's optional, Datadog highly recommends tagging you serverless applications with the `env`, `service`, and `version` tags following the [unified service tagging documentation][3].

## Explore Datadog Serverless Monitoring

After you have configured your function following the steps above, you can view metrics, logs and traces on the [Serverless Homepage][4].

### Monitor Custom Business Logic

If you would like to submit a custom metric or span, see the sample code below:

```python
import time
from ddtrace import tracer
from datadog_lambda.metric import lambda_metric

def lambda_handler(event, context):
    # add custom tags to the lambda function span,
    # does NOT work when X-Ray tracing is enabled
    current_span = tracer.current_span()
    if current_span:
        current_span.set_tag('customer.id', '123456')

    # submit a custom span
    with tracer.trace("hello.world"):
        print('Hello, World!')

    # submit a custom metric
    lambda_metric(
        metric_name='coffee_house.order_value',
        value=12.45,
        timestamp=int(time.time()), # optional, must be within last 20 mins
        tags=['product:latte', 'order:online']
    )

    return {
        'statusCode': 200,
        'body': get_message()
    }

# trace a function
@tracer.wrap()
def get_message():
    return 'Hello from serverless!'
```

For more information on custom metric submission, see [here][5]. For additional details on custom instrumentation, see the Datadog APM documentation for [custom instrumentation][6].

### Customize the Datadog Lambda Library

**IMPORTANT NOTE:** AWS Lambda is expected to recieve a [breaking change](https://aws.amazon.com/blogs/compute/upcoming-changes-to-the-python-sdk-in-aws-lambda/) on **April 1, 2021**. If you are using Datadog Python Lambda layer version 7 or below, please upgrade to the latest.

#### Tracing

For additional details on the tracer, check out the [official documentation for Datadog trace client](http://pypi.datadoghq.com/trace/docs/index.html).

#### Environment Variables

##### DD_FLUSH_TO_LOG

Set to `true` (recommended) to send custom metrics asynchronously (with no added latency to your Lambda function executions) through CloudWatch Logs with the help of [Datadog Forwarder](https://github.com/DataDog/datadog-serverless-functions/tree/main/aws/logs_monitoring). Defaults to `false`. If set to `false`, you also need to set `DD_API_KEY` and `DD_SITE`.

##### DD_API_KEY

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

##### DD_SITE

If `DD_FLUSH_TO_LOG` is set to `false` (not recommended), you must set `DD_SITE`. Possible values are `datadoghq.com`, `datadoghq.eu`, `us3.datadoghq.com` and `ddog-gov.com`. The default is `datadoghq.com`.

##### DD_LOGS_INJECTION

Inject Datadog trace id into logs for [correlation](https://docs.datadoghq.com/tracing/connect_logs_and_traces/python/). Defaults to `true`.

##### DD_LOG_LEVEL

Set to `debug` enable debug logs from the Datadog Lambda Library. Defaults to `info`.

##### DD_ENHANCED_METRICS

Generate enhanced Datadog Lambda integration metrics, such as, `aws.lambda.enhanced.invocations` and `aws.lambda.enhanced.errors`. Defaults to `true`.

##### DD_LAMBDA_HANDLER

Your original Lambda handler.

##### DD_TRACE_ENABLED

Initialize the Datadog tracer when set to `true`. Defaults to `false`.

##### DD_MERGE_XRAY_TRACES

Set to `true` to merge the X-Ray trace and the Datadog trace, when using both the X-Ray and Datadog tracing. Defaults to `false`.

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
