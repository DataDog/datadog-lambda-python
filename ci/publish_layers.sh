#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2023 Datadog, Inc.

# PYTHON_VERSION=20.9 REGION=us-east-1

set -e

# Available runtimes: https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
AWS_CLI_PYTHON_VERSIONS=(
    "python3.8"
    "python3.8"
    "python3.9"
    "python3.9"
    "python3.10"
    "python3.10"
    "python3.11"
    "python3.11"
    "python3.12"
    "python3.12"
    "python3.13"
    "python3.13"
)
PYTHON_VERSIONS=(
    "3.8-amd64"
    "3.8-arm64"
    "3.9-amd64"
    "3.9-arm64"
    "3.10-amd64"
    "3.10-arm64"
    "3.11-amd64"
    "3.11-arm64"
    "3.12-amd64"
    "3.12-arm64"
    "3.13-amd64"
    "3.13-arm64"
)
LAYER_PATHS=(
    ".layers/datadog_lambda_py-amd64-3.8.zip"
    ".layers/datadog_lambda_py-arm64-3.8.zip"
    ".layers/datadog_lambda_py-amd64-3.9.zip"
    ".layers/datadog_lambda_py-arm64-3.9.zip"
    ".layers/datadog_lambda_py-amd64-3.10.zip"
    ".layers/datadog_lambda_py-arm64-3.10.zip"
    ".layers/datadog_lambda_py-amd64-3.11.zip"
    ".layers/datadog_lambda_py-arm64-3.11.zip"
    ".layers/datadog_lambda_py-amd64-3.12.zip"
    ".layers/datadog_lambda_py-arm64-3.12.zip"
    ".layers/datadog_lambda_py-amd64-3.13.zip"
    ".layers/datadog_lambda_py-arm64-3.13.zip"
)
LAYERS=(
    "Datadog-Python38"
    "Datadog-Python38-ARM"
    "Datadog-Python39"
    "Datadog-Python39-ARM"
    "Datadog-Python310"
    "Datadog-Python310-ARM"
    "Datadog-Python311"
    "Datadog-Python311-ARM"
    "Datadog-Python312"
    "Datadog-Python312-ARM"
    "Datadog-Python313"
    "Datadog-Python313-ARM"
)
STAGES=('prod', 'sandbox', 'staging', 'gov-staging', 'gov-prod')

printf "Starting script...\n\n"

if [ -z "$SKIP_PIP_INSTALL" ]; then
    echo "Installing dependencies"
    pip install awscli
else
    echo "Skipping pip install"
fi

publish_layer() {
    region=$1
    layer_name=$2
    compatible_runtimes=$3
    layer_path=$4

    version_nbr=$(aws lambda publish-layer-version --layer-name $layer_name \
        --description "Datadog Lambda Layer for Python" \
        --zip-file "fileb://$layer_path" \
        --region $region \
        --compatible-runtimes $compatible_runtimes \
                        | jq -r '.Version')

    permission=$(aws lambda add-layer-version-permission --layer-name $layer_name \
        --version-number $version_nbr \
        --statement-id "release-$version_nbr" \
        --action lambda:GetLayerVersion --principal "*" \
        --region $region)

    echo $version_nbr
}

# Target Python version
if [ -z $PYTHON_VERSION ]; then
    printf "[Error] PYTHON_VERSION version not specified.\n"
    exit 1
fi

printf "Python version specified: $PYTHON_VERSION\n"
if [[ ! ${PYTHON_VERSIONS[@]} =~ $PYTHON_VERSION ]]; then
    printf "[Error] Unsupported PYTHON_VERSION found: $PYTHON_VERSION.\n"
    exit 1
fi

if [ -z $ARCH ]; then
    printf "[Error] ARCH architecture not specified.\n"
    exit 1
fi

index=0
for i in "${!PYTHON_VERSIONS[@]}"; do
    if [[ "${PYTHON_VERSIONS[$i]}" = "${PYTHON_VERSION}-${ARCH}" ]]; then
       index=$i
    fi
done

REGIONS=$(aws ec2 describe-regions | jq -r '.[] | .[] | .RegionName')

# Target region
if [ -z "$REGION" ]; then
    printf "REGION not specified.\n"
    exit 1
fi

printf "Region specified, region is: $REGION\n"
if [[ ! "$REGIONS" == *"$REGION"* ]]; then
    printf "[Error] Could not find $REGION in AWS available regions: \n${REGIONS[@]}\n"
    exit 1
fi

# Deploy stage
if [ -z "$STAGE" ]; then
    printf "[Error] STAGE not specified.\n"
    printf "Exiting script...\n"
    exit 1
fi

printf "Stage specified: $STAGE\n"
if [[ ! ${STAGES[@]} =~ $STAGE ]]; then
    printf "[Error] Unsupported STAGE found.\n"
    exit 1
fi

layer="${LAYERS[$index]}"
if [ -z "$LAYER_NAME_SUFFIX" ]; then
    echo "No layer name suffix"
else
    layer="${layer}-${LAYER_NAME_SUFFIX}"
fi
echo "layer name: $layer"

if [[ "$STAGE" =~ ^(staging|sandbox|gov-staging)$ ]]; then
    # Deploy latest version
    latest_version=$(aws lambda list-layer-versions --region $REGION --layer-name $layer --query 'LayerVersions[0].Version || `0`')
    VERSION=$(($latest_version + 1))
else
    # Running on prod
    if [ -z "$CI_COMMIT_TAG" ]; then
        printf "[Error] No CI_COMMIT_TAG found.\n"
        printf "Exiting script...\n"
        exit 1
    else
        printf "Tag found in environment: $CI_COMMIT_TAG\n"
    fi

    VERSION=$(echo "${CI_COMMIT_TAG##*v}" | cut -d. -f2)
fi

# Target layer version
if [ -z "$VERSION" ]; then
    printf "[Error] VERSION for layer version not specified.\n"
    printf "Exiting script...\n"
    exit 1
else
    printf "Layer version parsed: $VERSION\n"
fi

printf "[$REGION] Starting publishing layers...\n"
aws_cli_python_version_key="${AWS_CLI_PYTHON_VERSIONS[$index]}"
layer_path="${LAYER_PATHS[$index]}"

latest_version=$(aws lambda list-layer-versions --region $REGION --layer-name $layer --query 'LayerVersions[0].Version || `0`')
if [ $latest_version -ge $VERSION ]; then
    printf "[$REGION] Layer $layer version $VERSION already exists in region $REGION, skipping...\n"
    exit 0
elif [ $latest_version -lt $((VERSION-1)) ]; then
    printf "[$REGION][WARNING] The latest version of layer $layer in region $REGION is $latest_version, this will publish all the missing versions including $VERSION\n"
fi

while [ $latest_version -lt $VERSION ]; do
    latest_version=$(publish_layer $REGION $layer $aws_cli_python_version_key $layer_path)
    printf "[$REGION] Published version $latest_version for layer $layer in region $REGION\n"
    latest_arn=$(aws lambda get-layer-version --layer-name $layer --version-number $latest_version --region $REGION --query 'LayerVersionArn' --output text)
    printf "[$REGION] Published arn $latest_arn\n"

    # This shouldn't happen unless someone manually deleted the latest version, say 28, and
    # then tries to republish 28 again. The published version would actually be 29, because
    # Lambda layers are immutable and AWS will skip deleted version and use the next number.
    if [ $latest_version -gt $VERSION ]; then
        printf "[$REGION] Published version $latest_version is greater than the desired version $VERSION!"
        exit 1
    fi
done

printf "[$REGION] Finished publishing layers...\n\n"
