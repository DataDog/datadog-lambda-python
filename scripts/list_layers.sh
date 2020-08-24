#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

# Lists most recent layers ARNs across regions to STDOUT
# Optionals args: [layer-name] [region]

LAYER_NAMES=("Datadog-Python27" "Datadog-Python36" "Datadog-Python37" "Datadog-Python38")
REGULAR_REGIONS=(us-east-2 us-east-1 us-west-1 us-west-2 ap-east-1 ap-south-1 ap-northeast-2 ap-southeast-1 ap-southeast-2 ap-northeast-1 ca-central-1 eu-north-1 eu-central-1 eu-west-1 eu-west-2 eu-west-3 sa-east-1)
US_GOV_REGIONS=(us-gov-east-1 us-gov-west-1)
AVAILABLE_REGIONS=("${REGULAR_REGIONS[@]}" "${US_GOV_REGIONS[@]}")

# Check region arg
if [ -z "$1" ]; then
    >&2 echo "Region parameter not specified, running for all regular regions."
    REGIONS=("${REGULAR_REGIONS[@]}")
else
    >&2 echo "Region parameter specified: $1"
    if [[ ! " ${AVAILABLE_REGIONS[@]} " =~ " ${1} " ]]; then
        >&2 echo "Could not find $1 in available regions: ${AVAILABLE_REGIONS[@]}"
        >&2 echo ""
        >&2 echo "EXITING SCRIPT."
        exit 1
    fi
    REGIONS=($1)
fi

# Check layer arg
if [ -z "$2" ]; then
    >&2 echo "Layer parameter not specified, running for all layers "
    LAYERS=("${LAYER_NAMES[@]}")
else
    >&2 echo "Layer parameter specified: $2"
    if [[ ! " ${LAYER_NAMES[@]} " =~ " ${2} " ]]; then
        >&2 echo "Could not find $2 in layers: ${LAYER_NAMES[@]}"
        >&2 echo ""
        >&2 echo "EXITING SCRIPT."
        exit 1
    fi
    LAYERS=($2)
fi

for region in "${REGIONS[@]}"
do
    for layer_name in "${LAYERS[@]}"
    do
        last_layer_arn=$(aws lambda list-layer-versions --layer-name $layer_name --region $region | jq -r ".LayerVersions | .[0] |  .LayerVersionArn")
        if [ -z $last_layer_arn ]; then
             >&2 echo "No layer found for $region, $layer_name"
        else
            echo $last_layer_arn
        fi
    done
done
