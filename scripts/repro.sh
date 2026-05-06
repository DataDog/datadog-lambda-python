#!/usr/bin/env bash

# repro.sh
docker run --rm -it --platform linux/amd64 \
       -v $(pwd):/src \
       --workdir=/src \
       -e "UPSTREAM_PIPELINE_ID=main" \
       -e "PYTHONFAULTHANDLER=1" \
       -e "PYTHON_VERSION=3.11" \
       registry.ddbuild.io/images/mirror/python:3.11.6 bash -c "./scripts/setup_python_env.sh && source venv/bin/activate && pytest -vv"