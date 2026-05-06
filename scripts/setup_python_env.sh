#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).

# Sets up the Python environment for the lint, unit-test, and publish-pypi
# CI jobs (and for local repro of those flows). Replaces the inline
# .python-before-script anchor previously defined in
# ci/input_files/build.yaml.tpl.
#
# Steps:
#   1. (Optional) Rewrite pyproject.toml's ddtrace dep based on the
#      env-var contract documented in scripts/_spec_ddtrace_dep.sh
#      (DD_TRACE_COMMIT / DD_TRACE_COMMIT_BRANCH / DD_TRACE_WHEEL /
#      UPSTREAM_PIPELINE_ID). When dd-trace-py's CI triggers this repo's
#      pipeline it sets UPSTREAM_PIPELINE_ID, so the unit-test job
#      exercises the PR's wheel rather than the released ddtrace.
#   2. Create and activate a virtualenv ("venv/").
#   3. Install lambda-python's runtime + dev dependencies. pip resolves the
#      whole graph in one pass against the (possibly rewritten) pyproject.toml,
#      so any version conflicts surface as install errors instead of
#      runtime surprises.
#   4. Install poetry.
#
# Same dep-resolution path as scripts/build_layers.sh — both source
# scripts/_spec_ddtrace_dep.sh.
#
# DD_TRACE_COMMIT / DD_TRACE_COMMIT_BRANCH build ddtrace from source, which
# requires cargo, cmake, and a C/C++ toolchain — not present in the slim
# Python runner images. They are intended for local repro / git-bisect
# workflows. The dd-trace-py CI trigger uses UPSTREAM_PIPELINE_ID.
#
# Venv contract: this script sources venv/bin/activate inside its own
# subshell, so the activation does NOT persist into the calling job. Calling
# jobs must `source venv/bin/activate` themselves before running their
# command (matching the existing pattern in build.yaml.tpl).
#
# Environment variables:
#   PYTHON_VERSION   Python minor version (e.g. 3.12 or just 12). Required
#                    when the UPSTREAM_PIPELINE_ID branch is taken.
#   ARCH             "amd64" or "arm64". Required for correct ddtrace wheel
#                    selection when UPSTREAM_PIPELINE_ID is set (GitLab matrix
#                    should pass the runtime arch; if unset, host arch is used).

set -e

# Normalize Python version shorthand (e.g. 12 -> 3.12, 3.12 -> 3.12)
if [ -n "${PYTHON_VERSION:-}" ]; then
    if [[ "$PYTHON_VERSION" =~ ^[0-9]+$ ]]; then
        PYTHON_VERSION="3.${PYTHON_VERSION}"
    fi
fi

# Backup pyproject.toml so the rewrite doesn't persist across runs (matters
# for local invocations; CI runners are ephemeral but cheap to be tidy).
cp pyproject.toml pyproject.toml.bak
cleanup() {
    mv pyproject.toml.bak pyproject.toml 2>/dev/null || true
}
trap cleanup EXIT

source "$(dirname "$0")/_spec_ddtrace_dep.sh"
spec_ddtrace_dep

pip install virtualenv
virtualenv venv
source venv/bin/activate
pip install .[dev]
pip install poetry

python -c "import ddtrace; print('ddtrace version:', ddtrace.__version__)"
