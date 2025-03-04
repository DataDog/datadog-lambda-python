#! /usr/bin/env bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2025 Datadog, Inc.
#
# USAGE: download the layer bundle from the build pipeline in gitlab. Use the
# Download button on the `layer bundle` job. This will be a zip file containing
# all of the required layers. Run this script as follows:
#
# ENVIRONMENT=[us1-staging-fed or us1-fed] [LAYER_NAME_SUFFIX=optional-layer-suffix] [REGIONS=us-gov-west-1] ./scripts/publish_govcloud.sh <layer-bundle.zip>
#
# protip: you can drag the zip file from finder into your terminal to insert
# its path.

set -e

LAYER_PACKAGE=$1

if [ -z "$LAYER_PACKAGE" ]; then
    printf "[ERROR]: layer package not provided\n"
    exit 1
fi

PACKAGE_NAME=$(basename "$LAYER_PACKAGE" .zip)

if [ -z "$ENVIRONMENT" ]; then
    printf "[ERROR]: ENVIRONMENT not specified\n"
    exit 1
fi

if [ "$ENVIRONMENT" = "us1-staging-fed" ]; then
    AWS_VAULT_ROLE=sso-govcloud-us1-staging-fed-power-user

    export STAGE=gov-staging

    if [[ ! "$PACKAGE_NAME" =~ ^datadog_lambda_py-(signed-)?bundle-[0-9]+$ ]]; then
        echo "[ERROR]: Unexpected package name: $PACKAGE_NAME"
        exit 1
    fi

elif [ $ENVIRONMENT = "us1-fed" ]; then
    AWS_VAULT_ROLE=sso-govcloud-us1-fed-engineering

    export STAGE=gov-prod

    if [[ ! "$PACKAGE_NAME" =~ ^datadog_lambda_py-signed-bundle-[0-9]+$ ]]; then
        echo "[ERROR]: Unexpected package name: $PACKAGE_NAME"
        exit 1
    fi

else
    printf "[ERROR]: ENVIRONMENT not supported, must be us1-staging-fed or us1-fed.\n"
    exit 1
fi

TEMP_DIR=$(mktemp -d)
unzip $LAYER_PACKAGE -d $TEMP_DIR
cp -v $TEMP_DIR/$PACKAGE_NAME/*.zip .layers/


AWS_VAULT_PREFIX="aws-vault exec $AWS_VAULT_ROLE --"

echo "Checking that you have access to the GovCloud AWS account"
$AWS_VAULT_PREFIX aws sts get-caller-identity


AVAILABLE_REGIONS=$($AWS_VAULT_PREFIX aws ec2 describe-regions | jq -r '.[] | .[] | .RegionName')

# Determine the target regions
if [ -z "$REGIONS" ]; then
    echo "Region not specified, running for all available regions."
    REGIONS=$AVAILABLE_REGIONS
else
    echo "Region specified: $REGIONS"
    if [[ ! "$AVAILABLE_REGIONS" == *"$REGIONS"* ]]; then
        echo "Could not find $REGIONS in available regions: $AVAILABLE_REGIONS"
        echo ""
        echo "EXITING SCRIPT."
        exit 1
    fi
fi

for region in $REGIONS
do
    echo "Starting publishing layers for region $region..."

    export REGION=$region

    for python_version in "3.8" "3.9" "3.10" "3.11" "3.12" "3.13"; do
        for arch in "amd64" "arm64"; do
            export PYTHON_VERSION=$python_version
            export ARCH=$arch

            export SKIP_PIP_INSTALL=true

            echo "Publishing layer for $PYTHON_VERSION and $ARCH"

            $AWS_VAULT_PREFIX  ./ci/publish_layers.sh
        done
    done
done

echo "Done !"
