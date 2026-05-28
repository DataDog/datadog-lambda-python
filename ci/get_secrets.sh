#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2023 Datadog, Inc.

# Loads secrets for CI jobs from Vault (gitlab-runner path below).
#
# Full mode (default): requires EXTERNAL_ID_NAME, ROLE_TO_ASSUME, and AWS_ACCOUNT.
#   Fetches the external ID and DD API key, then assumes the AWS deployer role.
#
# API-key-only mode: set GET_SECRETS_API_KEY_ONLY=1 when sourcing.
#   Loads DD_API_KEY only (e.g. unit-test Test Optimization). Uses DD_API_KEY from
#   the environment when set; otherwise reads from Vault. Installs the vault CLI
#   on slim images that do not include it.

set -e

VAULT_SECRETS_PATH="kv/k8s/gitlab-runner/datadog-lambda-python/secrets"
VAULT_CLI_VERSION="${VAULT_CLI_VERSION:-1.18.5}"

_ensure_vault_cli() {
    command -v vault >/dev/null 2>&1 && return

    local arch install_dir
    case "$(uname -m)" in
        x86_64 | amd64) arch=amd64 ;;
        aarch64 | arm64) arch=arm64 ;;
        *) printf "[Error] Unsupported architecture: %s\n" "$(uname -m)" >&2; exit 1 ;;
    esac

    install_dir="${TMPDIR:-/tmp}/vault-cli-${VAULT_CLI_VERSION}-${arch}"
    if [ -x "${install_dir}/vault" ]; then
        export PATH="${install_dir}:${PATH}"
        return
    fi

    apt-get update -qq && apt-get install -y -qq curl unzip
    printf "Installing vault CLI %s (%s)...\n" "$VAULT_CLI_VERSION" "$arch"
    mkdir -p "$install_dir"
    curl -fsSL \
        "https://releases.hashicorp.com/vault/${VAULT_CLI_VERSION}/vault_${VAULT_CLI_VERSION}_linux_${arch}.zip" \
        -o "${install_dir}/vault.zip"
    unzip -qo "${install_dir}/vault.zip" -d "$install_dir"
    rm -f "${install_dir}/vault.zip"
    export PATH="${install_dir}:${PATH}"
}

_get_dd_api_key() {
    if [ -n "${DD_API_KEY:-}" ]; then
        printf "Using DD_API_KEY from environment.\n"
    else
        printf "Getting DD API KEY...\n"
        _ensure_vault_cli
        DD_API_KEY=$(vault kv get -field=dd-api-key "$VAULT_SECRETS_PATH")
        if [ -z "$DD_API_KEY" ]; then
            printf "[Error] DD_API_KEY is empty after Vault lookup.\n" >&2
            return 1 2>/dev/null || exit 1
        fi
        export DD_API_KEY
    fi

    if [ -n "${GITLAB_ENV:-}" ]; then
        echo "DD_API_KEY=${DD_API_KEY}" >>"$GITLAB_ENV"
    fi
}

if [ -n "${GET_SECRETS_API_KEY_ONLY:-}" ]; then
    _get_dd_api_key
    return 0 2>/dev/null || exit 0
fi

if [ -z "$EXTERNAL_ID_NAME" ]; then
    printf "[Error] No EXTERNAL_ID_NAME found.\n"
    printf "Exiting script...\n"
    exit 1
fi

if [ -z "$ROLE_TO_ASSUME" ]; then
    printf "[Error] No ROLE_TO_ASSUME found.\n"
    printf "Exiting script...\n"
    exit 1
fi

_ensure_vault_cli

printf "Getting AWS External ID...\n"

EXTERNAL_ID=$(vault kv get -field="$EXTERNAL_ID_NAME" "$VAULT_SECRETS_PATH")

_get_dd_api_key

printf "Assuming role...\n"

export $(printf "AWS_ACCESS_KEY_ID=%s AWS_SECRET_ACCESS_KEY=%s AWS_SESSION_TOKEN=%s" \
    $(aws sts assume-role \
    --role-arn "arn:aws:iam::$AWS_ACCOUNT:role/$ROLE_TO_ASSUME"  \
    --role-session-name "ci.datadog-lambda-python-$CI_JOB_ID-$CI_JOB_STAGE" \
    --query "Credentials.[AccessKeyId,SecretAccessKey,SessionToken]" \
    --external-id $EXTERNAL_ID \
    --output text))
