#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).

# Shared helpers for rewriting the ddtrace dependency in pyproject.toml.
# Sourced by scripts/build_layers.sh and scripts/setup_python_env.sh, so the
# layer build and the unit-test/lint/publish jobs use the same env-var
# contract and resolve the dep in a single pip pass.
#
# Env-var contract (highest precedence first):
#   DD_TRACE_COMMIT        Specific dd-trace-py commit SHA from GitHub.
#   DD_TRACE_COMMIT_BRANCH dd-trace-py branch name from GitHub.
#   DD_TRACE_WHEEL         Path to a pre-built ddtrace .whl file.
#   UPSTREAM_PIPELINE_ID   GitLab pipeline ID from dd-trace-py. Looks up the
#                          matching wheel from S3, trying the smaller
#                          serverless build first then falling back to the
#                          standard manylinux2014 build.
#
# When none of these are set, spec_ddtrace_dep is a no-op.
#
# When UPSTREAM_PIPELINE_ID is set, also requires:
#   PYTHON_VERSION  e.g. "3.12" (used to build the cpXY platform tag)
#   ARCH            "amd64" (default) or "arm64"

# Replace the ddtrace dependency block in pyproject.toml.
# Usage: replace_ddtrace_dep "ddtrace = { ... }"
replace_ddtrace_dep() {
    echo "Replacing ddtrace dep with: $1"
    perl -i -0777 -pe "s|ddtrace = \[[^\]]*\]|$1|gs" pyproject.toml
}

# Return 0 if Python $1 (e.g. "3.15") satisfies the Requires-Python of wheel $2.
# Handles the >=, >, <=, < and == bounds on major.minor; other clauses are
# ignored. A wheel without Requires-Python is accepted.
_wheel_supports_python() {
    local python_version=$1
    local wheel=$2
    local requires
    requires=$(unzip -p "$wheel" '*.dist-info/METADATA' 2>/dev/null \
        | sed -n 's/^Requires-Python: *//p' | head -n 1 | tr -d ' \r')
    [ -z "$requires" ] && return 0
    local want=$(( ${python_version%%.*} * 1000 + ${python_version#*.} ))
    local clause op ver major minor have
    IFS=',' read -ra clauses <<< "$requires"
    for clause in "${clauses[@]}"; do
        op=$(sed -E 's/^([<>=!~]+).*/\1/' <<< "$clause")
        ver=$(sed -E 's/^[<>=!~]+//' <<< "$clause")
        major=${ver%%.*}
        minor=$(cut -d. -f2 <<< "$ver.0")
        [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]] || continue
        have=$(( major * 1000 + minor ))
        case "$op" in
            ">=") [ "$want" -ge "$have" ] || return 1 ;;
            ">")  [ "$want" -gt "$have" ] || return 1 ;;
            "<=") [ "$want" -le "$have" ] || return 1 ;;
            "<")  [ "$want" -lt "$have" ] || return 1 ;;
            "==") [ "$want" -eq "$have" ] || return 1 ;;
        esac
    done
    return 0
}

# Search S3 for a wheel matching basename + index, then rewrite the ddtrace
# dep to point at the downloaded file. Globals required:
#   S3_BASE, PY_TAG, PLATFORM, PYTHON_VERSION
# Returns 0 on success, 1 if no matching wheel was found at the index, or if
# the wheel doesn't support PYTHON_VERSION (e.g. a dd-trace-py release branch
# older than the runtime): the caller then keeps the released ddtrace.
_search_and_spec_s3_wheel() {
    local basename=$1
    local index=$2
    local search_pattern="${basename}-[^\"]*${PY_TAG}[^\"]*${PLATFORM}[^\"]*\.whl"
    local index_url="${S3_BASE}/index-${index}.html"
    echo "Searching for wheel ${search_pattern} in ${index_url}"
    local wheel_file
    wheel_file=$(curl -sSfL "${index_url}" | grep -o "${search_pattern}" | head -n 1 || true)
    if [ -z "$wheel_file" ]; then
        return 1
    fi
    curl -sSfL "${S3_BASE}/${wheel_file}" -o "${wheel_file}"
    if ! _wheel_supports_python "${PYTHON_VERSION}" "${wheel_file}"; then
        echo "S3 wheel ${wheel_file} does not support Python ${PYTHON_VERSION}, not using it"
        rm -f "${wheel_file}"
        return 1
    fi
    echo "Using S3 wheel: ${wheel_file}"
    replace_ddtrace_dep "${basename} = { file = \"${wheel_file}\" }"
}

# Rewrite pyproject.toml's ddtrace dep based on the env-var precedence above.
# No-op if no override env var is set. Returns non-zero if UPSTREAM_PIPELINE_ID
# is set but no matching S3 wheel is found.
spec_ddtrace_dep() {
    if [ -n "${DD_TRACE_COMMIT:-}" ]; then
        replace_ddtrace_dep "ddtrace = { git = \"https://github.com/DataDog/dd-trace-py.git\", rev = \"${DD_TRACE_COMMIT}\" }"
    elif [ -n "${DD_TRACE_COMMIT_BRANCH:-}" ]; then
        replace_ddtrace_dep "ddtrace = { git = \"https://github.com/DataDog/dd-trace-py.git\", branch = \"${DD_TRACE_COMMIT_BRANCH}\" }"
    elif [ -n "${DD_TRACE_WHEEL:-}" ]; then
        local basename
        basename=$(sed 's/^.*\///' <<< "${DD_TRACE_WHEEL%%-*}")
        replace_ddtrace_dep "${basename} = { file = \"${DD_TRACE_WHEEL}\" }"
    elif [ -n "${UPSTREAM_PIPELINE_ID:-}" ]; then
        if [ -z "${PYTHON_VERSION:-}" ]; then
            echo "ERROR: PYTHON_VERSION must be set when UPSTREAM_PIPELINE_ID is set" >&2
            return 1
        fi
        S3_BASE="https://dd-trace-py-builds.s3.amazonaws.com/${UPSTREAM_PIPELINE_ID}"
        PY_TAG="cp$(echo "$PYTHON_VERSION" | tr -d '.')"
        if [ "$ARCH" = "amd64" ]; then
            PLATFORM="manylinux2014_x86_64"
        else
            PLATFORM="manylinux2014_aarch64"
        fi
        _search_and_spec_s3_wheel "ddtrace_serverless" "serverless" \
            || _search_and_spec_s3_wheel "ddtrace" "manylinux2014" \
            || { echo "ERROR: No matching ddtrace wheel for ${PY_TAG} ${PLATFORM} in pipeline ${UPSTREAM_PIPELINE_ID}, skipping version patch!" >&2; }
    fi
}
