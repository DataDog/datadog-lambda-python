#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

# Builds datadog-lambda-python layers for Lambda functions
#
# Usage:
#   PYTHON_VERSION=12 ARCH=arm ./scripts/build_layers.sh
#
# Environment variables:
#   PYTHON_VERSION  Python minor version. Accepts shorthand (e.g. 12) or full (e.g. 3.12).
#                   If not set, all supported versions are built.
#   ARCH            Target architecture. Accepts shorthand: arm, amd, x86, aarch64
#                   or full: arm64, amd64. If not set, both are built.
#
# dd-trace-py overrides (mutually exclusive, highest priority first):
#   DD_TRACE_COMMIT        Specific dd-trace-py commit SHA to build from GitHub.
#   DD_TRACE_COMMIT_BRANCH dd-trace-py branch name to build from GitHub.
#   DD_TRACE_WHEEL         Path to a pre-built ddtrace .whl file.
#   UPSTREAM_PIPELINE_ID   GitLab pipeline ID from dd-trace-py. Downloads the
#                          matching pre-built wheel from S3 (via
#                          index-manylinux2014.html) for each python/arch.
#
# Examples:
#   # Build a single layer for Python 3.12 on arm64
#   PYTHON_VERSION=12 ARCH=arm ./scripts/build_layers.sh
#
#   # Build with a specific dd-trace-py commit (for git bisect)
#   DD_TRACE_COMMIT=abc123 PYTHON_VERSION=12 ARCH=arm ./scripts/build_layers.sh

set -e

LAYER_DIR=".layers"
LAYER_FILES_PREFIX="datadog_lambda_py"
AVAILABLE_PYTHON_VERSIONS=("3.8" "3.9" "3.10" "3.11" "3.12" "3.13" "3.14")
AVAILABLE_ARCHS=("arm64" "amd64")

if [ -n "$ARCH" ]; then
    case "$ARCH" in
        arm|arm64|aarch64) ARCH="arm64" ;;
        amd|amd64|x86|x86_64) ARCH="amd64" ;;
    esac
fi

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
    ARCHS=("$ARCH")
fi

# Normalize Python version shorthand (e.g. 12 -> 3.12, 3.12 -> 3.12)
if [ -n "$PYTHON_VERSION" ]; then
    if [[ "$PYTHON_VERSION" =~ ^[0-9]+$ ]]; then
        PYTHON_VERSION="3.${PYTHON_VERSION}"
    fi
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
    PYTHON_VERSIONS=("$PYTHON_VERSION")
fi

# Backup pyproject.toml so modifications don't persist across runs
cp pyproject.toml pyproject.toml.bak
cleanup() {
    mv pyproject.toml.bak pyproject.toml 2>/dev/null || true
}
trap cleanup EXIT

# Helper: replace the multi-line ddtrace dependency in pyproject.toml.
# Uses perl instead of sed -z for macOS/Linux portability.
replace_ddtrace_dep() {
    perl -i -0777 -pe "s|ddtrace = \[[^\]]*\]|$1|gs" pyproject.toml
}

function make_path_absolute {
    echo "$(cd "$(dirname "$1")"; pwd)/$(basename "$1")"
}

function docker_build_zip {
    # Args: [python version] [zip destination]

    destination=$(make_path_absolute $2)
    arch=$3

    # Restore pyproject.toml to a clean state for each build iteration
    cp pyproject.toml.bak pyproject.toml

    # Remove any previously downloaded wheels
    rm -f ddtrace-*.whl

    # Replace ddtrace source if necessary
    if [ -n "$DD_TRACE_COMMIT" ]; then
        replace_ddtrace_dep "ddtrace = { git = \"https://github.com/DataDog/dd-trace-py.git\", rev = \"$DD_TRACE_COMMIT\" }"
    elif [ -n "$DD_TRACE_COMMIT_BRANCH" ]; then
        replace_ddtrace_dep "ddtrace = { git = \"https://github.com/DataDog/dd-trace-py.git\", branch = \"$DD_TRACE_COMMIT_BRANCH\" }"
    elif [ -n "$DD_TRACE_WHEEL" ]; then
        replace_ddtrace_dep "ddtrace = { file = \"$DD_TRACE_WHEEL\" }"
    elif [ -n "$UPSTREAM_PIPELINE_ID" ]; then
        S3_BASE="https://dd-trace-py-builds.s3.amazonaws.com/${UPSTREAM_PIPELINE_ID}"
        if [ "${arch}" = "amd64" ]; then
            PLATFORM="manylinux2014_x86_64"
        else
            PLATFORM="manylinux2014_aarch64"
        fi
        PY_TAG="cp$(echo "$1" | tr -d '.')"
        WHEEL_FILE=$(curl -sSfL "${S3_BASE}/index-manylinux2014.html" \
            | grep -o "ddtrace-[^\"]*${PY_TAG}[^\"]*${PLATFORM}[^\"]*\.whl" \
            | head -n 1)
        if [ -z "${WHEEL_FILE}" ]; then
            echo "Error: no wheel found for ${PY_TAG} ${PLATFORM} in ${S3_BASE}/index-manylinux2014.html" >&2
            exit 1
        fi
        curl -sSfL "${S3_BASE}/${WHEEL_FILE}" -o "${WHEEL_FILE}"
        echo "Using S3 wheel: ${WHEEL_FILE}"
        replace_ddtrace_dep "ddtrace = { file = \"${WHEEL_FILE}\" }"
    fi

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
