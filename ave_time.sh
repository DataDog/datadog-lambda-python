#!/bin/bash

set -e

time (
    export DD_LAMBDA_HANDLER=builtins.print

    for _ in {1..100}
    do
        python -c "import datadog_lambda.handler"
    done
) 2>&1
