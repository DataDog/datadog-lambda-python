#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

# Run unit tests in Docker
set -e

source "$(dirname "${BASH_SOURCE[0]}")/python_versions.sh"
load_python_versions

for python_version in "${SUPPORTED_PYTHON_VERSIONS[@]}"
do
    echo "Running tests against python${python_version}"
    docker build -t datadog-lambda-python-test:$python_version \
        -f tests/Dockerfile . \
        --build-arg python_version=$python_version
    docker run -w /test \
        datadog-lambda-python-test:$python_version \
        pytest -vv
    docker run -w /test \
        datadog-lambda-python-test:$python_version \
        flake8 datadog_lambda/
done
