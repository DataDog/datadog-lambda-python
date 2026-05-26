#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).

# Loads DD_API_KEY from Vault for CI jobs that need Datadog API access without
# assuming an AWS role (e.g. unit-test Test Optimization agentless reporting).

set -e

printf "Getting DD API KEY...\n"

export DD_API_KEY=$(vault kv get -field=dd-api-key kv/k8s/gitlab-runner/datadog-lambda-python/secrets)
