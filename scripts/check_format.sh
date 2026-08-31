#!/bin/sh
set -e

python -m black --check datadog_lambda/ --diff
python -m black --check tests --diff



