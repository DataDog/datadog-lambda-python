#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2026 Datadog, Inc.

# Reads python_versions.yaml. Source this file; do not execute it from other
# scripts. Pure bash (3.2+) so layer builds do not need jq, yq, or Python.
#
#   source scripts/python_versions.sh
#   load_python_versions
#
# After load_python_versions:
#   SUPPORTED_PYTHON_VERSIONS              "3.8" "3.9" ...
#   SUPPORTED_PYTHON_VERSION_IMAGES        parallel to versions
#   SUPPORTED_PYTHON_VERSION_PREVIEW       "true" / "false"
#   SUPPORTED_PYTHON_VERSION_SYSTEM_TESTS  "true" / "false"
#
#   python_version_known <version>
#   python_version_is_preview <version>
#   python_versions_json [system_tests|preview]
#
# After load_python_layers (calls load_python_versions if needed), one entry
# per version for amd64 then arm64:
#   LAYER_NAMES      Datadog-Python38, Datadog-Python38-ARM, ...
#   LAYER_RUNTIMES   python3.8, python3.8, ...
#   LAYER_ZIPS       datadog_lambda_py-amd64-3.8.zip, ...
#   LAYER_PATHS      .layers/datadog_lambda_py-amd64-3.8.zip, ...
#   LAYER_VERSIONS   3.8, 3.8, ...
#   LAYER_ARCHS      amd64, arm64, ...

_PYTHON_VERSIONS_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/python_versions.yaml"

_pv_trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

_pv_unquote() {
    local s="$1"
    local first last
    first="${s%"${s#?}"}"
    last="${s#"${s%?}"}"
    if [ ${#s} -ge 2 ] && [ "$first" = "$last" ] && { [ "$first" = '"' ] || [ "$first" = "'" ]; }; then
        s="${s#?}"
        s="${s%?}"
    fi
    printf '%s' "$s"
}

_pv_reset_entry() {
    _pv_version=""
    _pv_image=""
    _pv_preview=""
    _pv_system_tests=""
}

_pv_flush_entry() {
    if [ -z "${_pv_version}" ]; then
        return 0
    fi
    local existing
    if [ "${#SUPPORTED_PYTHON_VERSIONS[@]}" -gt 0 ]; then
        for existing in "${SUPPORTED_PYTHON_VERSIONS[@]}"; do
            if [ "$existing" = "$_pv_version" ]; then
                echo "duplicate python version in ${PYTHON_VERSIONS_FILE}: ${_pv_version}" >&2
                return 1
            fi
        done
    fi
    if [ -z "${_pv_image}" ]; then
        echo "python version ${_pv_version} is missing image in ${PYTHON_VERSIONS_FILE}" >&2
        return 1
    fi
    if [ -z "${_pv_preview}" ]; then
        _pv_preview="false"
    fi
    if [ -z "${_pv_system_tests}" ]; then
        _pv_system_tests="true"
    fi
    SUPPORTED_PYTHON_VERSIONS+=("$_pv_version")
    SUPPORTED_PYTHON_VERSION_IMAGES+=("$_pv_image")
    SUPPORTED_PYTHON_VERSION_PREVIEW+=("$_pv_preview")
    SUPPORTED_PYTHON_VERSION_SYSTEM_TESTS+=("$_pv_system_tests")
    _pv_reset_entry
}

_pv_set_field() {
    local key="$1"
    local value="$2"
    case "$key" in
        image) _pv_image="$value" ;;
        preview)
            case "$value" in
                true|false) _pv_preview="$value" ;;
                *)
                    echo "python version ${_pv_version}: preview must be true or false, got '${value}'" >&2
                    return 1
                    ;;
            esac
            ;;
        system_tests)
            case "$value" in
                true|false) _pv_system_tests="$value" ;;
                *)
                    echo "python version ${_pv_version}: system_tests must be true or false, got '${value}'" >&2
                    return 1
                    ;;
            esac
            ;;
        *)
            echo "unknown field '${key}' in ${PYTHON_VERSIONS_FILE}" >&2
            return 1
            ;;
    esac
}

load_python_versions() {
    PYTHON_VERSIONS_FILE="${PYTHON_VERSIONS_FILE:-$_PYTHON_VERSIONS_FILE}"
    if [ ! -f "$PYTHON_VERSIONS_FILE" ]; then
        echo "python versions config not found: $PYTHON_VERSIONS_FILE" >&2
        return 1
    fi

    SUPPORTED_PYTHON_VERSIONS=()
    SUPPORTED_PYTHON_VERSION_IMAGES=()
    SUPPORTED_PYTHON_VERSION_PREVIEW=()
    SUPPORTED_PYTHON_VERSION_SYSTEM_TESTS=()
    _python_versions_loaded=0
    _pv_reset_entry

    local line key value seen_versions=0
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%%#*}"
        line="${line%$'\r'}"
        line="$(_pv_trim "$line")"
        if [ -z "$line" ]; then
            continue
        fi
        if [ "$line" = "versions:" ]; then
            seen_versions=1
            continue
        fi
        if [ "$seen_versions" -ne 1 ]; then
            echo "unexpected line in ${PYTHON_VERSIONS_FILE}: ${line}" >&2
            return 1
        fi
        if [[ "$line" =~ ^-[[:space:]]+version:[[:space:]]*(.*)$ ]]; then
            _pv_flush_entry || return 1
            value="$(_pv_unquote "$(_pv_trim "${BASH_REMATCH[1]}")")"
            if [[ ! "$value" =~ ^[0-9]+\.[0-9]+$ ]]; then
                echo "invalid python version '${value}' in ${PYTHON_VERSIONS_FILE}" >&2
                return 1
            fi
            _pv_version="$value"
            continue
        fi
        if [ -z "${_pv_version}" ]; then
            echo "field before version in ${PYTHON_VERSIONS_FILE}: ${line}" >&2
            return 1
        fi
        if [[ "$line" =~ ^([A-Za-z_]+):[[:space:]]*(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            value="$(_pv_unquote "$(_pv_trim "${BASH_REMATCH[2]}")")"
            _pv_set_field "$key" "$value" || return 1
            continue
        fi
        echo "could not parse line in ${PYTHON_VERSIONS_FILE}: ${line}" >&2
        return 1
    done < "$PYTHON_VERSIONS_FILE"

    _pv_flush_entry || return 1
    if [ "${#SUPPORTED_PYTHON_VERSIONS[@]}" -eq 0 ]; then
        echo "no python versions found in ${PYTHON_VERSIONS_FILE}" >&2
        return 1
    fi
    _python_versions_loaded=1
}

_python_version_index() {
    local target="$1"
    local i
    if [ "${_python_versions_loaded:-0}" -ne 1 ]; then
        echo "load_python_versions must be called first" >&2
        return 1
    fi
    for i in "${!SUPPORTED_PYTHON_VERSIONS[@]}"; do
        if [ "${SUPPORTED_PYTHON_VERSIONS[$i]}" = "$target" ]; then
            printf '%s' "$i"
            return 0
        fi
    done
    return 1
}

python_version_known() {
    _python_version_index "$1" >/dev/null
}

python_version_is_preview() {
    local i
    i="$(_python_version_index "$1")" || return 1
    [ "${SUPPORTED_PYTHON_VERSION_PREVIEW[$i]}" = "true" ]
}

python_runtime_name() {
    printf 'python%s' "$1"
}

python_layer_name() {
    local version="$1"
    local arch="$2"
    local suffix="${version//./}"
    case "$arch" in
        amd64) printf 'Datadog-Python%s' "$suffix" ;;
        arm64) printf 'Datadog-Python%s-ARM' "$suffix" ;;
        *)
            echo "unknown architecture '${arch}'" >&2
            return 1
            ;;
    esac
}

python_layer_zip() {
    printf 'datadog_lambda_py-%s-%s.zip' "$2" "$1"
}

python_layer_path() {
    printf '.layers/%s' "$(python_layer_zip "$1" "$2")"
}

python_layer_matrix() {
    if [ "${_python_versions_loaded:-0}" -ne 1 ]; then
        echo "load_python_versions must be called first" >&2
        return 1
    fi
    local version
    for version in "${SUPPORTED_PYTHON_VERSIONS[@]}"; do
        printf '%s %s\n' "$version" "amd64"
        printf '%s %s\n' "$version" "arm64"
    done
}

load_python_layers() {
    if [ "${_python_versions_loaded:-0}" -ne 1 ]; then
        load_python_versions || return 1
    fi
    LAYER_NAMES=()
    LAYER_PATHS=()
    LAYER_ZIPS=()
    LAYER_RUNTIMES=()
    LAYER_VERSIONS=()
    LAYER_ARCHS=()
    local version arch
    while IFS=' ' read -r version arch; do
        if [ -z "$version" ]; then
            continue
        fi
        LAYER_VERSIONS+=("$version")
        LAYER_ARCHS+=("$arch")
        LAYER_NAMES+=("$(python_layer_name "$version" "$arch")")
        LAYER_ZIPS+=("$(python_layer_zip "$version" "$arch")")
        LAYER_PATHS+=("$(python_layer_path "$version" "$arch")")
        LAYER_RUNTIMES+=("$(python_runtime_name "$version")")
    done <<EOF
$(python_layer_matrix)
EOF
}

# JSON array of versions. Optional filter: system_tests or preview.
python_versions_json() {
    local only="${1:-}"
    if [ "${_python_versions_loaded:-0}" -ne 1 ]; then
        echo "load_python_versions must be called first" >&2
        return 1
    fi
    local json="["
    local first=1
    local i version include
    for i in "${!SUPPORTED_PYTHON_VERSIONS[@]}"; do
        version="${SUPPORTED_PYTHON_VERSIONS[$i]}"
        include=1
        case "$only" in
            "") ;;
            system_tests)
                if [ "${SUPPORTED_PYTHON_VERSION_SYSTEM_TESTS[$i]}" != "true" ]; then
                    include=0
                fi
                ;;
            preview)
                if [ "${SUPPORTED_PYTHON_VERSION_PREVIEW[$i]}" != "true" ]; then
                    include=0
                fi
                ;;
            *)
                echo "unknown python_versions_json filter: ${only}" >&2
                return 1
                ;;
        esac
        if [ "$include" -eq 1 ]; then
            if [ "$first" -eq 0 ]; then
                json="${json},"
            fi
            first=0
            json="${json}\"${version}\""
        fi
    done
    json="${json}]"
    printf '%s' "$json"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    load_python_versions
    load_python_layers
    i=0
    while [ "$i" -lt "${#SUPPORTED_PYTHON_VERSIONS[@]}" ]; do
        extra=""
        if [ "${SUPPORTED_PYTHON_VERSION_PREVIEW[$i]}" = "true" ]; then
            extra="${extra} preview"
        fi
        if [ "${SUPPORTED_PYTHON_VERSION_SYSTEM_TESTS[$i]}" != "true" ]; then
            extra="${extra} system_tests=false"
        fi
        printf '%s image=%s%s\n' \
            "${SUPPORTED_PYTHON_VERSIONS[$i]}" \
            "${SUPPORTED_PYTHON_VERSION_IMAGES[$i]}" \
            "$extra"
        i=$((i + 1))
    done
fi
