#!/bin/sh

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

# Builds Datadogpy layers for lambda functions, using Docker
set -e

python -m grpc_tools.protoc -I datadog_lambda/pb/ --python_out=datadog_lambda/pb/ --grpc_python_out=datadog_lambda/pb/ ./datadog_lambda/pb/*.proto