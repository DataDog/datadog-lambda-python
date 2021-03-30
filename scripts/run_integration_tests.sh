#!/bin/bash

# Usage - run commands from repo root:
# To check if new changes to the layer cause changes to any snapshots:
#   BUILD_LAYERS=true DD_API_KEY=XXXX aws-vault exec sandbox-account-admin -- ./scripts/run_integration_tests
# To regenerate snapshots:
#   UPDATE_SNAPSHOTS=true DD_API_KEY=XXXX aws-vault exec sandbox-account-admin -- ./scripts/run_integration_tests

set -e

# These values need to be in sync with serverless.yml, where there needs to be a function
# defined for every handler_runtime combination
LAMBDA_HANDLERS=("async-metrics" "sync-metrics" "http-requests" "http-error")
RUNTIMES=("python27" "python36" "python37" "python38")

LOGS_WAIT_SECONDS=20

script_path=${BASH_SOURCE[0]}
scripts_dir=$(dirname $script_path)
repo_dir=$(dirname $scripts_dir)
integration_tests_dir="$repo_dir/tests/integration"

script_utc_start_time=$(date -u +"%Y%m%dT%H%M%S")

mismatch_found=false

if [ -z "$DD_API_KEY" ]; then
    echo "No DD_API_KEY env var set, exiting"
    exit 1
fi

if [ -n "$UPDATE_SNAPSHOTS" ]; then
    echo "Overwriting snapshots in this execution"
fi

if [ -n "$BUILD_LAYERS" ]; then
    echo "Building layers that will be deployed with our test functions"
    source $scripts_dir/build_layers.sh
else
    echo "Not building layers, ensure they've already been built or re-run with 'BUILD_LAYERS=true DD_API_KEY=XXXX ./scripts/run_integration_tests.sh'"
fi

cd $integration_tests_dir

input_event_files=$(ls ./input_events)
# Sort event files by name so that snapshots stay consistent
input_event_files=($(for file_name in ${input_event_files[@]}; do echo $file_name; done | sort))

# Generate a random 8-character ID to avoid collisions with other runs
run_id=$(xxd -l 4 -c 4 -p < /dev/random)

echo "Deploying functions"
serverless deploy --stage $run_id

echo "Invoking functions"
set +e # Don't exit this script if an invocation fails or there's a diff
for handler_name in "${LAMBDA_HANDLERS[@]}"; do
    for runtime in "${RUNTIMES[@]}"; do
        function_name="${handler_name}_${runtime}"

        # Invoke function once for each input event
        for input_event_file in "${input_event_files[@]}"; do
            # Get event name without trailing ".json" so we can build the snapshot file name
            input_event_name=$(echo "$input_event_file" | sed "s/.json//")
            snapshot_path="./snapshots/return_values/${function_name}_${input_event_name}.json"

            return_value=$(serverless invoke -f $function_name --stage $run_id --path "./input_events/$input_event_file")

            if [ ! -f $snapshot_path ]; then
                # If the snapshot file doesn't exist yet, we create it
                echo "Writing return value to $snapshot_path because no snapshot exists yet"
                echo "$return_value" >$snapshot_path
            elif [ -n "$UPDATE_SNAPSHOTS" ]; then
                # If $UPDATE_SNAPSHOTS is set to true, write the new logs over the current snapshot
                echo "Overwriting return value snapshot for $snapshot_path"
                echo "$return_value" >$snapshot_path
            else
                # Compare new return value to snapshot
                diff_output=$(echo "$return_value" | diff - $snapshot_path)
                if [ $? -eq 1 ]; then
                    echo "Failed: Return value for $function_name does not match snapshot:"
                    echo "$diff_output"
                    mismatch_found=true
                else
                    echo "Ok: Return value for $function_name with $input_event_name event matches snapshot"
                fi
            fi
        done
    done
done
set -e

echo "Sleeping $LOGS_WAIT_SECONDS seconds to wait for logs to appear in CloudWatch..."
sleep $LOGS_WAIT_SECONDS

set +e # Don't exit this script if there is a diff or the logs endpoint fails
echo "Fetching logs for invocations and comparing to snapshots"
for handler_name in "${LAMBDA_HANDLERS[@]}"; do
    for runtime in "${RUNTIMES[@]}"; do
        function_name="${handler_name}_${runtime}"
        function_snapshot_path="./snapshots/logs/$function_name.log"

        # Fetch logs with serverless cli, retrying to avoid AWS account-wide rate limit error
        retry_counter=0
        while [ $retry_counter -lt 10 ]; do
            raw_logs=$(serverless logs -f $function_name --stage $run_id --startTime $script_utc_start_time)
            fetch_logs_exit_code=$?
            if [ $fetch_logs_exit_code -eq 1 ]; then
                echo "Retrying fetch logs for $function_name..."
                retry_counter=$(($retry_counter + 1))
                sleep 10
                continue
            fi
            break
        done

        if [ $retry_counter -eq 9 ]; then
            echo "FAILURE: Could not retrieve logs for $function_name"
            echo "Error from final attempt to retrieve logs:"
            echo $raw_logs

            echo "Removing functions"
            serverless remove --stage $run_id

            exit 1
        fi

        # Replace invocation-specific data like timestamps and IDs with XXXX to normalize logs across executions
        logs=$(
            echo "$raw_logs" |
                # Filter serverless cli errors
                sed '/Serverless: Recoverable error occurred/d' |
                # Remove RequestsDependencyWarning from botocore/vendored/requests/__init__.py
                sed '/RequestsDependencyWarning/d' |
                # Remove blank lines
                sed '/^$/d' |
                # Normalize Lambda runtime REPORT logs
                sed -E 's/(RequestId|TraceId|SegmentId|Duration|Memory Used|"e"): [a-z0-9\.\-]+/\1: XXXX/g' |
                # Normalize HTTP headers
                sed -E "s/(x-datadog-parent-id:|x-datadog-trace-id:|Content-Length:)[0-9]+/\1XXXX/g" |
                # Remove Account ID
                sed -E "s/(account_id:)[0-9]+/\1XXXX/g" |
                # Normalize timestamps in datapoints POSTed to DD
                sed -E 's/"points": \[\[[0-9\.]+,/"points": \[\[XXXX,/g' |
                # Strip API key from logged requests
                sed -E "s/(api_key=|'api_key': ')[a-z0-9\.\-]+/\1XXXX/g" |
                # Normalize minor package version so that these snapshots aren't broken on version bumps
                sed -E "s/(dd_lambda_layer:datadog-python[0-9]+_2\.)[0-9]+\.0/\1XX\.0/g" |
                sed -E "s/(datadog_lambda:v)([0-9]+\.[0-9]+\.[0-9])/\1XX/g" |
                # Strip out run ID (from function name, resource, etc.)
                sed -E "s/$run_id/XXXX/g" |
                # Strip out trace/span/parent/timestamps
                sed -E "s/(\"trace_id\"\: \")[A-Z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"span_id\"\: \")[A-Z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"parent_id\"\: \")[A-Z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"request_id\"\: \")[a-z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"duration\"\: )[0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"start\"\: )[0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"system\.pid\"\: )[0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"runtime-id\"\: \")[a-z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"datadog_lambda\"\: \")([0-9]+\.[0-9]+\.[0-9])/\1X.X.X/g" |
                sed -E "s/(\"dd_trace\"\: \")([0-9]+\.[0-9]+\.[0-9])/\1X.X.X/g"
        )

        if [ ! -f $function_snapshot_path ]; then
            # If no snapshot file exists yet, we create one
            echo "Writing logs to $function_snapshot_path because no snapshot exists yet"
            echo "$logs" >$function_snapshot_path
        elif [ -n "$UPDATE_SNAPSHOTS" ]; then
            # If $UPDATE_SNAPSHOTS is set to true write the new logs over the current snapshot
            echo "Overwriting log snapshot for $function_snapshot_path"
            echo "$logs" >$function_snapshot_path
        else
            # Compare new logs to snapshots
            diff_output=$(echo "$logs" | diff - $function_snapshot_path)
            if [ $? -eq 1 ]; then
                echo "Failed: Mismatch found between new $function_name logs (first) and snapshot (second):"
                echo "$diff_output"
                mismatch_found=true
            else
                echo "Ok: New logs for $function_name match snapshot"
            fi
        fi
    done
done
set -e

echo "Removing functions"
serverless remove --stage $run_id

if [ "$mismatch_found" = true ]; then
    echo "FAILURE: A mismatch between new data and a snapshot was found and printed above."
    echo "If the change is expected, generate new snapshots by running 'UPDATE_SNAPSHOTS=true DD_API_KEY=XXXX ./scripts/run_integration_tests.sh'"
    echo "Make sure https://httpstat.us/400/ is UP for `http_error` test case"
    exit 1
fi

if [ -n "$UPDATE_SNAPSHOTS" ]; then
    echo "SUCCESS: Wrote new snapshots for all functions"
    exit 0
fi

echo "SUCCESS: No difference found between snapshots and new return values or logs"
