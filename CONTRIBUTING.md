# Contributing

We love pull requests. Here's a quick guide.

1. Fork, clone and branch off `main`:
    ```bash
    git clone git@github.com:<your-username>/datadog-lambda-python.git
    git checkout -b <my-branch>
    ```
1. Make your changes. Ensure your code is compatible with both Python 2.7 and 3.X. 
1. Test your Lambda function against the locally modified version of Datadog Lambda library.
   * The easiest approach is to create a soft link of the `datadog_lambda` folder in your project's root. Note, this only overrides the `datadog_lambda` module, and you still need to install the `datadog_lambda` package or the Lambda layer to have the required dependencies.

     ```bash
     ln -s /PATH/TO/datadog-lambda-python/datadog_lambda /PATH/TO/MY/PROJECT
     ```
   * Another option is to install the `datadog_lambda` module from the local folder. E.g., add `/PATH/TO/datadog-lambda-python/` to your `requirements.txt`. This approach only work in a Linux environment, because the dependency `ddtrace` utilizes the native C extension.
   * You can also build and publish a Lambda layer to your own AWS account and use it for testing.

     ```bash
     # Build layers using docker
     ./scripts/build_layers.sh

     # Publish the a testing layer to your own AWS account, and the ARN will be returned
     # Example: VERSION=1 REGIONS=us-east-1 LAYERS=Datadog-Python37 ./scripts/publish_layers.sh
     VERSION=<VERSION> REGIONS=<REGION> LAYERS=<LAYER> ./scripts/publish_layers.sh
     ```

1. Ensure the unit tests pass (install Docker if you haven't):
    ```bash
    ./scripts/run_tests.sh
    ```
1. Run the integration tests against your own AWS account and Datadog org (or ask a Datadog member to run):
   ```bash
   BUILD_LAYERS=true DD_API_KEY=<your Datadog api key> ./scripts/run_integration_tests.sh
   ```
1. Update integration test snapshots if needed:
   ```bash
   UPDATE_SNAPSHOTS=true DD_API_KEY=<your Datadog api key> ./scripts/run_integration_tests.sh
   ```
1. Push to your fork and [submit a pull request][pr].

[pr]: https://github.com/your-username/datadog-lambda-python/compare/DataDog:main...main

At this point you're waiting on us. We may suggest some changes or improvements or alternatives.
