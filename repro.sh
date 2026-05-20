#!/usr/bin/env bash

# repro.sh
docker run --rm -it --platform linux/amd64 \
       -v $(pwd):/src \
       --workdir=/src \
       -e "UPSTREAM_PIPELINE_ID=112946992" \
       -e "PYTHONFAULTHANDLER=1" \
       -e "PYTHON_VERSION=3.11" \
       -e "DD_PROFILING_ENABLED=true" \
       -e "DD_PROFILING_ADAPTIVE_SAMPLING_ENABLED=false" \
       -e "_DD_PROFILING_STACK_FAST_COPY=true" \
       -e "ARCH=amd64" \
       registry.ddbuild.io/images/mirror/python:3.11.6 bash -c "./scripts/setup_python_env.sh && source venv/bin/activate && pytest -vv"