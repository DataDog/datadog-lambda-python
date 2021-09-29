#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

# Builds datadog-lambda-python layers for Lambda functions

# Usage: PYTHON_VERSION=3.7 ./build_layers.sh
# If PYTHON_VERSION is not specified, all versions will be built.

set -e

LAYER_DIR=".layers"
LAYER_FILES_PREFIX="datadog_lambda_py"
AVAILABLE_PYTHON_VERSIONS=("2.7" "3.6" "3.7" "3.8" "3.9")

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
        --build-arg image=python:$1 \
        --build-arg runtime=python$1 \
        --platform linux/${arch} \
        --load

    # Run the image by runtime tag, tar its generatd `python` directory to sdout,
    # then extract it to a temp directory.
    docker run datadog-lambda-python-${arch}:$1 tar cf - python | tar -xf - -C $temp_dir


    # Zip to destination, and keep directory structure as based in $temp_dir
    (cd $temp_dir && zip -q -r $destination ./)

    rm -rf $temp_dir
    echo "Done creating archive $destination"
}

rm -rf $LAYER_DIR
mkdir $LAYER_DIR

for python_version in "${PYTHON_VERSIONS[@]}"
do
    if [ "$python_version" == "3.8" ]; then
        echo "Building layer for Python ${python_version} arch=arm64"
        docker_build_zip ${python_version} $LAYER_DIR/${LAYER_FILES_PREFIX}-arm64-${python_version}.zip arm64
    fi
    echo "Building layer for Python ${python_version} arch=amd64"
    docker_build_zip ${python_version} $LAYER_DIR/${LAYER_FILES_PREFIX}-amd64-${python_version}.zip amd64
done

echo "Done creating layers:"
ls $LAYER_DIR | xargs -I _ echo "$LAYER_DIR/_"
