#!/bin/bash -e

# This script checks to make sure that the vendored version of requests shipped
# with pip meets the minimum required version of requests as defined by the
# datadog package.

if [[ -z $PYTHON_VERSION ]]; then
    PYTHON_VERSION=latest
fi

# create virtual environment
rm -rf venv
pip install virtualenv
virtualenv venv
source venv/bin/activate

# determine highest available version of requests
pip install .
highest=$(pip freeze | grep requests | tr -d 'requests==')
echo "Highest available version of requests: $highest"

# determine minumum required version of requests
pip uninstall -y requests
pip install uv
uv pip install --resolution=lowest .
lowest=$(pip freeze | grep requests | tr -d 'requests==')
echo "Minimum required version of requests: $lowest"

# determine version of requests packaged with pip
vendored=$(
    docker run \
        --entrypoint='' \
            public.ecr.aws/lambda/python:$PYTHON_VERSION \
            python -c "import pip._vendor.requests; print(pip._vendor.requests.__version__)"
)
echo "Version of vendored requests: $vendored"

# compare versions
compared=$(python -c "
parse = lambda v: tuple(map(int, v.split('.')))
print(parse('$lowest') <= parse('$vendored'))")

if [[ "$compared" == "True" ]]; then
    echo "The vendored version of requests meets the minimum requirement"
    echo "  lowest required ($lowest) <= vendored version ($vendored) <= highest available ($highest)"
else
    echo "The vendored version of requests does not meet the minimum requirement"
    echo "  vendered version ($vendored) < lowest required ($lowest) <= highest available ($highest)"
    exit 1
fi
