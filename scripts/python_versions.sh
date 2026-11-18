#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2026 Datadog, Inc.

# Reads python_versions.yaml. Source this file:
#
#   source scripts/python_versions.sh
#
# Sets:
#   SUPPORTED_PYTHON_VERSIONS  3.8 3.9 ...
#   PREVIEW_PYTHON_VERSIONS    versions with preview: true
# and, one entry per version for amd64 then arm64:
#   LAYER_NAMES     Datadog-Python38, Datadog-Python38-ARM, ...
#   LAYER_RUNTIMES  python3.8, python3.8, ...
#   LAYER_KEYS      3.8-amd64, 3.8-arm64, ...
#   LAYER_ZIPS      datadog_lambda_py-amd64-3.8.zip, ...
#   LAYER_PATHS     .layers/datadog_lambda_py-amd64-3.8.zip, ...

_pv_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/python_versions.yaml"

SUPPORTED_PYTHON_VERSIONS=($(sed -nE 's/^[[:space:]]*- version:[[:space:]]*"?([0-9]+\.[0-9]+)"?.*/\1/p' "$_pv_file"))
PREVIEW_PYTHON_VERSIONS=($(awk -F'"' '/- version:/{v=$2} /^[[:space:]]*preview:[[:space:]]*true/{print v}' "$_pv_file"))
if [ ${#SUPPORTED_PYTHON_VERSIONS[@]} -eq 0 ]; then
    echo "no python versions found in $_pv_file" >&2
    return 1
fi

LAYER_NAMES=()
LAYER_RUNTIMES=()
LAYER_KEYS=()
LAYER_ZIPS=()
for _pv_version in "${SUPPORTED_PYTHON_VERSIONS[@]}"; do
    for _pv_arch in amd64 arm64; do
        _pv_suffix=""
        [ "$_pv_arch" = arm64 ] && _pv_suffix="-ARM"
        LAYER_NAMES+=("Datadog-Python${_pv_version//./}${_pv_suffix}")
        LAYER_RUNTIMES+=("python${_pv_version}")
        LAYER_KEYS+=("${_pv_version}-${_pv_arch}")
        LAYER_ZIPS+=("datadog_lambda_py-${_pv_arch}-${_pv_version}.zip")
    done
done
LAYER_PATHS=("${LAYER_ZIPS[@]/#/.layers/}")
unset _pv_file _pv_version _pv_arch _pv_suffix
