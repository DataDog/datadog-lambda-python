#!/bin/bash

# Usage: VERSION=5 ./scripts/publish_sandbox.sh
set -e

# Build only ARM64 layers for Python 3.12
ARCH=arm64 PYTHON_VERSION=3.12 ./scripts/build_layers.sh
# Signing is commented out for sandbox - not needed for internal testing
## aws-vault exec sso-serverless-sandbox-account-admin -- ./scripts/sign_layers.sh sandbox
# Publish to us-east-1 only
LAYERS=John-Datadog-Python312-ARM VERSION=$VERSION REGIONS=us-east-1 aws-vault exec sso-serverless-sandbox-account-admin -- ./scripts/publish_layers.sh

# Automatically create PR against github.com/DataDog/documentation
# If you'd like to test, please uncomment the below line
# VERSION=$VERSION LAYER=datadog-lambda-python ./scripts/create_documentation_pr.sh
