#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

# Builds datadog-lambda-python layers for Lambda functions

# Usage: PYTHON_VERSION=3.11 ./build_layers.sh
# If PYTHON_VERSION is not specified, all versions will be built.

set -e

LAYER_DIR=".layers"
LAYER_FILES_PREFIX="datadog_lambda_py"
AVAILABLE_PYTHON_VERSIONS=("3.8" "3.9" "3.10" "3.11" "3.12" "3.13" "3.14")
AVAILABLE_ARCHS=("arm64" "amd64")

if [ -z "$ARCH" ]; then
    echo "No architectures specified, building layers for all architectures."
    ARCHS=("${AVAILABLE_ARCHS[@]}")
else
    echo "Architecture specified: $ARCH"
    if [[ ! " ${AVAILABLE_ARCHS[@]} " =~ " ${ARCH} " ]]; then
        echo "Architecture $ARCH is not a valid option. Choose from: ${AVAILABLE_ARCHS[@]}"
        echo ""
        echo "EXITING SCRIPT."
        exit 1
    fi
    ARCHS=$ARCH
fi

# Determine which Python versions to build layers for
if [ -z "$PYTHON_VERSION" ]; then
    echo "Python version not specified, building layers for all versions."
    PYTHON_VERSIONS=("${AVAILABLE_PYTHON_VERSIONS[@]}")
else
    echo "Python version specified: $PYTHON_VERSION"
    if [[ ! " ${AVAILABLE_PYTHON_VERSIONS[@]} " =~ " ${PYTHON_VERSION} " ]]; then
        echo "Python version $PYTHON_VERSION is not a valid option. Choose from: ${AVAILABLE_PYTHON_VERSIONS[@]}"
        echo ""
        echo "EXITING SCRIPT."
        exit 1
    fi
    PYTHON_VERSIONS=$PYTHON_VERSION
fi

echo "DD_TRACE_COMMIT_BRANCH: $DD_TRACE_COMMIT_BRANCH"
echo "DD_TRACE_WHEEL: $DD_TRACE_WHEEL"
if [ -z "$DD_TRACE_COMMIT_BRANCH" ]; then
    echo "commit branch!"
    sed -z -E -i 's|(ddtrace = )\[[^]]*]|\1{ git = "https://github.com/DataDog/dd-trace-py.git", branch = \"'"$DD_TRACE_COMMIT_BRANCH"'\" }|g' pyproject.toml
else
    if [ -z "$DD_TRACE_WHEEL" ]; then
        echo "wheel!"
        sed -z -E -i 's|(ddtrace = )\[[^]]*]|\1{ file = "'"$DD_TRACE_WHEEL"'" }|g' pyproject.toml
        echo "sed -z -E -i 's|(ddtrace = )\[[^]]*]|\1{ file = "'"$DD_TRACE_WHEEL"'" }|g' pyproject.toml"
    fi
fi

function make_path_absolute {
    echo "$(cd "$(dirname "$1")"; pwd)/$(basename "$1")"
}

function docker_build_zip {
    # Args: [python version] [zip destination]

    destination=$(make_path_absolute $2)
    arch=$3

    # Install datadogpy in a docker container to avoid the mess from switching
    # between different python runtimes.
    temp_dir=$(mktemp -d)
    docker buildx build -t datadog-lambda-python-${arch}:$1 . --no-cache \
        --build-arg image=public.ecr.aws/sam/build-python$1:1 \
        --build-arg runtime=python$1 \
        --platform linux/${arch} \
        --progress=plain \
        -o $temp_dir/python

    # Zip to destination, and keep directory structure as based in $temp_dir
    (cd $temp_dir && zip -q -r $destination ./)

    rm -rf $temp_dir
    echo "Done creating archive $destination"
}

rm -rf $LAYER_DIR
mkdir $LAYER_DIR

for python_version in "${PYTHON_VERSIONS[@]}"
do
    for architecture in "${ARCHS[@]}"
    do
        echo "Building layer for Python ${python_version} arch=${architecture}"
        docker_build_zip ${python_version} $LAYER_DIR/${LAYER_FILES_PREFIX}-${architecture}-${python_version}.zip ${architecture}
    done
done

echo "Done creating layers:"
ls $LAYER_DIR | xargs -I _ echo "$LAYER_DIR/_"
