#!/bin/sh

# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2019 Datadog, Inc.

# Builds the lambda layer and upload to Pypi
set -e

# Clear previously built distributions
if [ -d "dist" ]; then
    echo "Removing folder 'dist' to clear previously built distributions"
    rm -rf dist;
fi

# Install build tools
pip install --upgrade setuptools wheel twine

# Build distributions
python setup.py sdist bdist_wheel

# Upload distributions
python -m twine upload dist/*
