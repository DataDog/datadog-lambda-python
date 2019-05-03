#!/bin/sh

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

# Builds Datadogpy layers for lambda functions, using Docker
set -e

LAYER_DIR=".layers"
LAYER_FILES_PREFIX="datadog_lambda_py"
PYTHON_VERSIONS=("2.7" "3.6" "3.7")

function make_path_absolute {
    echo "$(cd "$(dirname "$1")"; pwd)/$(basename "$1")"
}

function docker_build_zip {
    # Args: [python version] [zip destination]

    destination=$(make_path_absolute $2)

    # Install datadogpy in a docker container to avoid the mess from switching
    # between different python runtimes.
    temp_dir=$(mktemp -d)
    docker build -t datadog-lambda-layer-python:$1 . --no-cache \
        --build-arg image=python:$1 \
        --build-arg runtime=python$1

    # Run the image by runtime tag, tar its generatd `python` directory to sdout,
    # then extract it to a temp directory.
    docker run datadog-lambda-layer-python:$1 tar cf - python | tar -xf - -C $temp_dir

    # Zip to destination, and keep directory structure as based in $temp_dir
    (cd $temp_dir && zip -q -r $destination ./)

    rm -rf $temp_dir
    echo "Done creating archive $destination"
}

rm -rf $LAYER_DIR
mkdir $LAYER_DIR

for python_version in "${PYTHON_VERSIONS[@]}"
do
    echo "Building layer for python${python_version}"
    docker_build_zip ${python_version} $LAYER_DIR/${LAYER_FILES_PREFIX}${python_version}.zip
done


echo "Done creating layers:"
ls $LAYER_DIR | xargs -I _ echo "$LAYER_DIR/_"
