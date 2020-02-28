#!/bin/bash

# Stop execution if any command has errors
set -e

# These values need to be in sync with serverless.yml, where there needs to be a function
# defined for every handler-runtime combination
LAMBDA_HANDLERS=("async-metrics" "sync-metrics" "http-requests")
RUNTIMES=("python27" "python36" "python37" "python38")

LOGS_WAIT_SECONDS=20

script_path=${BASH_SOURCE[0]}
scripts_dir=$(dirname $script_path)
repo_dir=$(dirname $scripts_dir)
integration_tests_dir="$repo_dir/tests/integration"

script_start_time=$(date --iso-8601=seconds)

mismatch_found=false

echo "Start time is $script_start_time"

if [ -n "$UPDATE_SNAPSHOTS" ]; then
    echo "Overwriting snapshots in this execution"
fi

if [ -z "$DD_API_KEY" ]; then
    echo "No DD_API_KEY env var set, exiting"
    exit 1
fi

if [ -n "$BUILD_LAYERS" ]; then
    echo "Building layers that will be deployed with our test functions"
    source $scripts_dir/build_layers.sh
else
    echo "Not building layers, ensure they've already been built or re-run with 'REBUILD_LAYERS=true ./scripts/run_integration_tests.sh'"
fi

echo "Deploying functions"
cd $integration_tests_dir
serverless deploy

echo "Invoking functions"
set +e # Don't exit this script if an invocation fails
for handler_name in "${LAMBDA_HANDLERS[@]}"; do
    for runtime in "${RUNTIMES[@]}"; do
        function_name="$handler_name-$runtime"
        function_snapshot_path="./snapshots/$function_name.return_value"

        return_value=$(serverless invoke -f $function_name)

        if [ -n "$UPDATE_SNAPSHOTS" ] || [ ! -f $function_snapshot_path ]; then
            # If $UPDATE_SNAPSHOTS is set to true, write the new logs over the current snapshot
            echo "Writing return value snapshot for $function_name"
            echo "$return_value" >$function_snapshot_path
        else
            # Compare new return value to snapshot
            diff_output=$(echo "$return_value" | diff - $function_snapshot_path)
            if [ $? -eq 1 ]; then
                echo "Failed: Return value for $function_name does not match snapshot:"
                echo "$diff_output"
                mismatch_found=true
            else
                echo "Ok: Return value for $function_name matches snapshot"
            fi
        fi
    done
done

set -e

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

        # Replace invocation-specific data like timestamps and IDs with XXXX to normalize logs across executions
        # Normalize Lambda runtime report logs
        logs=$(echo "$logs" | sed -E 's/(RequestId|TraceId|SegmentId|Duration|Memory Used|"e"): [a-z0-9\.\-]+/\1: XXXX/g')
        # Normalize DD APM headers
        logs=$(echo "$logs" | sed -E "s/(x-datadog-parent-id:|x-datadog-trace-id:)[0-9]+/\1XXXX/g")
        # Normalize timestamps in datapoints POSTed to DD
        logs=$(echo "$logs" | sed -E 's/"points": \[\[[0-9\.]+,/"points": \[\[XXXX,/g')
        # # Normalize invocation IDs used in requests to the Lambda runtime
        # logs=$(echo "$logs" | sed -E 's/\/2018-06-01\/runtime\/invocation\/[a-z0-9-]+/\/2018-06-01\/runtime\/invocation\/XXXX/g')
        # Strip API key from logged requests
        logs=$(echo "$logs" | sed -E "s/(api_key=|'api_key': ')[a-z0-9\.\-]+/\1XXXX/g")

        if [ -n "$UPDATE_SNAPSHOTS" ] || [ ! -f $function_snapshot_path ]; then
            # If $UPDATE_SNAPSHOTS is set to true write the new logs over the current snapshot
            # If no file exists yet, we create one
            echo "Writing log snapshot for $function_name"
            echo "$logs" >$function_snapshot_path
        else
            # Compare new logs to snapshots
            set +e # Don't exit this script if there is a diff
            diff_output=$(echo "$logs" | diff - $function_snapshot_path)
            if [ $? -eq 1 ]; then
                echo "Failed: Mismatch found between new $function_name logs (first) and snapshot (second):"
                echo "$diff_output"
                mismatch_found=true
            else
                echo "Ok: New logs for $function_name match snapshot"
            fi
            set -e
        fi
    done
done

if [ "$mismatch_found" = true ]; then
    echo "FAILURE: A mismatch between new data and a snapshot was found and printed above. If the change is expected, generate new snapshots by running 'UPDATE_SNAPSHOTS=true ./scripts/run_integration_tests.sh'"
    exit 1
fi

if [ -n "$UPDATE_SNAPSHOTS" ]; then
    echo "SUCCESS: Wrote new snapshots for all functions"
    exit 0
fi

echo "SUCCESS: No difference found between new logs and snapshots"
