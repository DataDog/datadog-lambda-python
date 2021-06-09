#!/bin/sh
set -e

PYTHON_VERSION=$(python -c 'import sys; print(sys.version_info.major)')
if [ "$PYTHON_VERSION" = "2" ]; then
    echo "Skipping formatting, black not compatible with python 2"
    exit 0
fi
pip install -Iv black==20.8b1

python -m black --check datadog_lambda/ --diff
python -m black --check tests --diff



