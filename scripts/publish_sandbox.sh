#!/bin/bash

# Usage: VERSION=5 ./scripts/publish_sandbox.sh
set -e

./scripts/build_layers.sh
aws-vault exec sandbox-account-admin -- ./scripts/sign_layers.sh sandbox
aws-vault exec sandbox-account-admin -- ./scripts/publish_layers.sh

# Automatically create PR against github.com/DataDog/documentation
# If you'd like to test, please uncomment the below line
# VERSION=$VERSION LAYER=datadog-lambda-python ./scripts/create_documentation_pr.sh
