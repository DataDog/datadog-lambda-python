#!/bin/bash

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

# Lists most recent layers ARNs across regions to STDOUT
# Optionals args: [layer-name] [region]

# Source the common list of layers and regions
source scripts/all_layers.sh

# Check region arg
if [ -z "$2" ]; then
    >&2 echo "Region parameter not specified, running for all available regions."
    REGIONS=("${AVAILABLE_REGIONS[@]}")
else
    >&2 echo "Region parameter specified: $2"
    if [[ ! " ${AVAILABLE_REGIONS[@]} " =~ " ${2} " ]]; then
        >&2 echo "Could not find $2 in available regions: ${AVAILABLE_REGIONS[@]}"
        >&2 echo ""
        >&2 echo "EXITING SCRIPT."
        return 1
    fi
    REGIONS=($2)
fi

# Check region arg
if [ -z "$1" ]; then
    >&2 echo "Layer parameter not specified, running for all layers "
    LAYERS=("${AVAILABLE_LAYER_NAMES[@]}")
else
    >&2 echo "Layer parameter specified: $1"
    if [[ ! " ${AVAILABLE_LAYER_NAMES[@]} " =~ " ${1} " ]]; then
        >&2 echo "Could not find $1 in layers: ${AVAILABLE_LAYER_NAMES[@]}"
        >&2 echo ""
        >&2 echo "EXITING SCRIPT."
        return 1
    fi
    LAYERS=($1)
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
