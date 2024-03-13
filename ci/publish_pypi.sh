#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2023 Datadog, Inc.
set -e
PYPI_TOKEN=$(aws ssm get-parameter \
    --region us-east-1 \
    --name "ci.datadog-lambda-python.pypi-token" \
    --with-decryption \
    --query "Parameter.Value" \
    --out text)
# Builds the lambda layer and upload to Pypi

if [ -z "$CI_COMMIT_TAG" ]; then
    printf "[Error] No CI_COMMIT_TAG found.\n"
    printf "Exiting script...\n"
    # exit 1
else
    printf "Tag found in environment: $CI_COMMIT_TAG\n"
fi

# Clear previously built distributions
if [ -d "dist" ]; then
    echo "Removing folder 'dist' to clear previously built distributions"
    rm -rf dist;
fi

# Publish to pypi
poetry publish --build --username __token__ --password $PYPI_TOKEN --dry-run
