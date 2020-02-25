#!/bin/bash

set -e

# These values need to be in sync with serverless.yml, where there needs to be a function
# defined for every handler-runtime combination
LAMBDA_HANDLERS=("async-metrics")
RUNTIMES=("python27" "python36" "python37" "python38")

LOGS_WAIT_SECONDS=20

script_path=${BASH_SOURCE[0]}
scripts_dir=$(dirname $script_path)
repo_dir=$(dirname $scripts_dir)
integration_tests_dir="$repo_dir/tests/integration"

script_start_time=$(date --iso-8601=seconds)

echo "Start time is $script_start_time"

echo "Building new layers that will be uploaded with our test functions"
# source $scripts_dir/build_layers.sh

echo "Deploying functions"
cd $integration_tests_dir
serverless deploy

echo "Invoking functions"
for handler_name in "${LAMBDA_HANDLERS[@]}"; do
    for runtime in "${RUNTIMES[@]}"; do
        echo "Invoking $handler_name-$runtime"
        serverless invoke -f "$handler_name-$runtime"
    done
done

echo "Sleeping for $LOGS_WAIT_SECONDS seconds to wait for logs to appear in CloudWatch..."
sleep $LOGS_WAIT_SECONDS

echo "Fetching logs for invocations and comparing to snapshots"
for handler_name in "${LAMBDA_HANDLERS[@]}"; do
    for runtime in "${RUNTIMES[@]}"; do
        logs=$(serverless logs -f "$handler_name-$runtime" --startTime $script_start_time)
        python compare_to_snapshots.py "$handler_name-$runtime" "$logs"
    done
done

# Go back to the repo root
cd $repo_dir

# Download the new CloudWatch logs for each Lambda

# Filter out all logs that aren't metrics and traces and compare to the snapshots in this repo
