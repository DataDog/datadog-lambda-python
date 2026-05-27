#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).

# Loads DD_API_KEY for CI jobs that need Datadog API access without assuming an
# AWS role (e.g. unit-test Test Optimization agentless reporting).
#
# Resolution order:
#   1. Use DD_API_KEY if already set (e.g. GitLab CI/CD project variable).
#   2. Read from Vault via the gitlab-runner secrets path (requires vault CLI).
#
# Slim python CI images do not ship vault; the script installs a static binary
# when needed. Runners must provide VAULT_ADDR / VAULT_TOKEN for Vault auth.

set -e

VAULT_SECRETS_PATH="kv/k8s/gitlab-runner/datadog-lambda-python/secrets"
VAULT_CLI_VERSION="${VAULT_CLI_VERSION:-1.18.5}"

_ensure_vault_cli() {
    if command -v vault >/dev/null 2>&1; then
        return 0
    fi

    local arch
    case "$(uname -m)" in
        x86_64 | amd64) arch=amd64 ;;
        aarch64 | arm64) arch=arm64 ;;
        *)
            printf "[Error] Unsupported architecture for vault install: %s\n" "$(uname -m)" >&2
            exit 1
            ;;
    esac

    local install_dir="${TMPDIR:-/tmp}/vault-cli-${VAULT_CLI_VERSION}-${arch}"
    mkdir -p "$install_dir"

    if [ ! -x "${install_dir}/vault" ]; then
        if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
            apt-get update -qq
            apt-get install -y -qq curl unzip
        fi

        local zip_url="https://releases.hashicorp.com/vault/${VAULT_CLI_VERSION}/vault_${VAULT_CLI_VERSION}_linux_${arch}.zip"
        printf "Installing vault CLI %s (%s)...\n" "$VAULT_CLI_VERSION" "$arch"
        curl -fsSL "$zip_url" -o "${install_dir}/vault.zip"
        unzip -qo "${install_dir}/vault.zip" -d "$install_dir"
        rm -f "${install_dir}/vault.zip"
    fi

    export PATH="${install_dir}:${PATH}"
}

_export_dd_api_key() {
    export DD_API_KEY

    if [ -n "${GITLAB_ENV:-}" ]; then
        echo "DD_API_KEY=${DD_API_KEY}" >>"$GITLAB_ENV"
    fi
}

if [ -n "${DD_API_KEY:-}" ]; then
    printf "Using DD_API_KEY from environment.\n"
else
    printf "Getting DD API KEY from Vault...\n"

    _ensure_vault_cli

    DD_API_KEY=$(vault kv get -field=dd-api-key "$VAULT_SECRETS_PATH")

    if [ -z "$DD_API_KEY" ]; then
        printf "[Error] DD_API_KEY is empty after Vault lookup.\n" >&2
        return 1 2>/dev/null || exit 1
    fi
fi

_export_dd_api_key
