#!/bin/bash

# Stop execution if any command has errors
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

mismatch_found=false

echo "Start time is $script_start_time"

echo "Building layers that will be deployed with our test functions"
# source $scripts_dir/build_layers.sh

if [ -n "$OVERWRITE" ]; then
    echo "Overwriting snapshots in this execution"
fi

echo "Deploying functions"
cd $integration_tests_dir
serverless deploy

echo "Invoking functions"
for handler_name in "${LAMBDA_HANDLERS[@]}"; do
    for runtime in "${RUNTIMES[@]}"; do
        function_name="$handler_name-$runtime"
        function_snapshot_path="./snapshots/$function_name.return_value"

        return_value=$(serverless invoke -f $function_name)

        if [ -n "$OVERWRITE" ]; then
            # If $OVERWRITE is set to true, write the new logs over the current snapshot
            echo "Overwriting return value snapshot for $function_name"
            echo "$return_value" >$function_snapshot_path
        else
            # Compare new return value to snapshot
            set +e # Don't exit this script if there is a diff
            diff_output=$(echo "$return_value" | diff - $function_snapshot_path)
            if [ $? -eq 1 ]; then
                echo "FAILURE: Return value for $function_name does not match snapshot:"
                echo "$diff_output"
                mismatch_found=true
            else
                echo "SUCCESS: Return value for $function_name matches snapshot"
            fi
            set -e
        fi
    done
done

echo "Sleeping $LOGS_WAIT_SECONDS seconds to wait for logs to appear in CloudWatch..."
sleep $LOGS_WAIT_SECONDS

echo "Fetching logs for invocations and comparing to snapshots"
for handler_name in "${LAMBDA_HANDLERS[@]}"; do
    for runtime in "${RUNTIMES[@]}"; do
        function_name="$handler_name-$runtime"
        function_snapshot_path="./snapshots/$function_name.logs"

        # Fetch logs with serverless cli
        logs=$(serverless logs -f $function_name --startTime $script_start_time)

        # Filter serverless cli errors
        logs=$(echo "$logs" | sed '/Serverless: Recoverable error occurred/d')

        # Replace invocation-specific data with XXXX to normalize between executions
        logs=$(echo "$logs" | sed -E 's/(RequestId|TraceId|SegmentId|Duration|Memory Used|"e"): [a-z0-9\.\-]+/\1: XXXX/g')

        if [ -n "$OVERWRITE" ]; then
            # If $OVERWRITE is set to true, write the new logs over the current snapshot
            echo "Overwriting snapshot for $function_name"
            echo "$logs" >$function_snapshot_path
        else
            # Compare new logs to snapshots
            set +e # Don't exit this script if there is a diff
            diff_output=$(echo "$logs" | diff - $function_snapshot_path)
            if [ $? -eq 1 ]; then
                echo "FAILURE: Mismatch found between new $function_name logs and snapshot:"
                echo "$diff_output"
                mismatch_found=true
            else
                echo "SUCCESS: New logs for $function_name match snapshot"
            fi
            set -e
        fi
    done
done

if [ "$mismatch_found" = true ]; then
    echo "TEST FAILED: A mismatch between newly generated logs and a snapshot was found above. If this is expected, re-run this script with OVERWRITE=true to generate new snapshots"
    exit 1
fi

echo "TEST SUCCEEDED: No difference found between new logs and snapshots"
