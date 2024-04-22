#!/bin/bash

set -e

PYTHON_VERSION=3.9 ARCH=amd64 ./scripts/build_layers.sh

cd .layers/
unzip datadog_lambda_py-amd64-3.9.zip
cd -

docker run -it \
    --platform=linux/amd64 \
    -v "$PWD"/.layers/python/lib/python3.9/site-packages:/opt/python/lib/python3.9/site-packages/ \
    --entrypoint='' \
    -e PYTHONPATH=/opt/python/lib/python3.9/site-packages \
        public.ecr.aws/lambda/python:3.9 \
            python /opt/python/lib/python3.9/site-packages/datadog_lambda/tracing.py
