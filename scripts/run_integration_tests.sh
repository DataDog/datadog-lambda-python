#!/bin/bash

# Usage - run commands from repo root:
# To check if new changes to the layer cause changes to any snapshots:
#   BUILD_LAYERS=true DD_API_KEY=XXXX aws-vault exec sso-serverless-sandbox-account-admin -- ./scripts/run_integration_tests.sh
# To regenerate snapshots:
#   UPDATE_SNAPSHOTS=true DD_API_KEY=XXXX aws-vault exec sso-serverless-sandbox-account-admin -- ./scripts/run_integration_tests.sh

set -e

# These values need to be in sync with serverless.yml, where there needs to be a function
# defined for every handler_runtime combination
LAMBDA_HANDLERS=("async-metrics" "sync-metrics")

LOGS_WAIT_SECONDS=20

script_path=${BASH_SOURCE[0]}
scripts_dir=$(dirname $script_path)
repo_dir=$(dirname $scripts_dir)
integration_tests_dir="$repo_dir/tests/integration"

script_utc_start_time=$(date -u +"%Y%m%dT%H%M%S")

mismatch_found=false

# Format :
# [0]: serverless runtime name
# [1]: python version
# [2]: random 8-character ID to avoid collisions with other runs
python38=("python3.8" "3.8" $(xxd -l 4 -c 4 -p < /dev/random))
python39=("python3.9" "3.9" $(xxd -l 4 -c 4 -p < /dev/random))
python310=("python3.10" "3.10" $(xxd -l 4 -c 4 -p < /dev/random))
python311=("python3.11" "3.11" $(xxd -l 4 -c 4 -p < /dev/random))
python312=("python3.12" "3.12" $(xxd -l 4 -c 4 -p < /dev/random))
python313=("python3.13" "3.13" $(xxd -l 4 -c 4 -p < /dev/random))

PARAMETERS_SETS=("python38" "python39" "python310" "python311" "python312" "python313")

if [ -z "$RUNTIME_PARAM" ]; then
    echo "Python version not specified, running for all python versions."
else
    RUNTIME_PARAM_NO_DOT=$(echo $RUNTIME_PARAM | sed 's/\.//')
    echo "Python version is specified: $RUNTIME_PARAM"
    PARAMETERS_SETS=(python${RUNTIME_PARAM_NO_DOT})
    BUILD_LAYER_VERSION=python$RUNTIME_PARAM_NO_DOT[1]
fi


if [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    echo "No AWS credentials were found in the environment."
    echo "Note that only Datadog employees can run these integration tests."
    exit 1
fi

if [ -z "$DD_API_KEY" ]; then
    echo "No DD_API_KEY env var set, exiting"
    exit 1
fi

if [ -z "$ARCH" ]; then
    echo "No ARCH env var set, exiting"
    exit 1
fi

if [ -n "$UPDATE_SNAPSHOTS" ]; then
    echo "Overwriting snapshots in this execution"
fi

if [ -n "$BUILD_LAYERS" ]; then
    echo "Building layers that will be deployed with our test functions"
    if [ -n "$BUILD_LAYER_VERSION" ]; then
        PYTHON_VERSION=${!BUILD_LAYER_VERSION} source $scripts_dir/build_layers.sh
    else
        source $scripts_dir/build_layers.sh
    fi
else
    echo "Not building layers, ensure they've already been built or re-run with 'BUILD_LAYERS=true DD_API_KEY=XXXX ./scripts/run_integration_tests.sh'"
fi

SERVERLESS_FRAMEWORK_ARCH=""
if [ "$ARCH" = "amd64" ]; then
    SERVERLESS_FRAMEWORK_ARCH="x86_64"
else
    SERVERLESS_FRAMEWORK_ARCH="arm64"
fi
cd $integration_tests_dir

input_event_files=$(ls ./input_events)
# Sort event files by name so that snapshots stay consistent
input_event_files=($(for file_name in ${input_event_files[@]}; do echo $file_name; done | sort))

# Always remove the stack(s) before exiting, no matter what
function remove_stack() {
    for parameters_set in "${PARAMETERS_SETS[@]}"; do
        serverless_runtime=$parameters_set[0]
        python_version=$parameters_set[1]
        run_id=$parameters_set[2]
        echo "Removing stack for stage : ${!run_id}"
        PYTHON_VERSION=${!python_version} RUNTIME=$parameters_set SERVERLESS_RUNTIME=${!serverless_runtime} SLS_ARCH=${SERVERLESS_FRAMEWORK_ARCH} \
        serverless remove --stage ${!run_id}
    done
}

trap remove_stack EXIT
for parameters_set in "${PARAMETERS_SETS[@]}"; do
    serverless_runtime=$parameters_set[0]
    python_version=$parameters_set[1]
    run_id=$parameters_set[2]

    echo "Deploying functions for runtime : $parameters_set, serverless runtime : ${!serverless_runtime}, \
python version : ${!python_version} and run id : ${!run_id}"

    PYTHON_VERSION=${!python_version} RUNTIME=$parameters_set SERVERLESS_RUNTIME=${!serverless_runtime} ARCH=${ARCH} SLS_ARCH=${SERVERLESS_FRAMEWORK_ARCH} \
    serverless deploy --stage ${!run_id}

    echo "Invoking functions for runtime $parameters_set"
    set +e # Don't exit this script if an invocation fails or there's a diff
    for handler_name in "${LAMBDA_HANDLERS[@]}"; do
        function_name="${handler_name}_python"
        echo "$function_name"
        # Invoke function once for each input event
        for input_event_file in "${input_event_files[@]}"; do
            # Get event name without trailing ".json" so we can build the snapshot file name
            input_event_name=$(echo "$input_event_file" | sed "s/.json//")
            snapshot_path="./snapshots/return_values/${handler_name}_${input_event_name}.json"

            return_value=$(PYTHON_VERSION=${!python_version} RUNTIME=$parameters_set SERVERLESS_RUNTIME=${!serverless_runtime} SLS_ARCH=${SERVERLESS_FRAMEWORK_ARCH} \
            serverless invoke --stage ${!run_id} -f "$function_name" --path "./input_events/$input_event_file")

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
    for parameters_set in "${PARAMETERS_SETS[@]}"; do
        function_name="${handler_name}_python"
        function_snapshot_path="./snapshots/logs/${handler_name}_${parameters_set}.log"
        serverless_runtime=$parameters_set[0]
        python_version=$parameters_set[1]
        run_id=$parameters_set[2]
        # Fetch logs with serverless cli, retrying to avoid AWS account-wide rate limit error
        retry_counter=0
        while [ $retry_counter -lt 10 ]; do
            raw_logs=$(PYTHON_VERSION=${!python_version} RUNTIME=$parameters_set SERVERLESS_RUNTIME=${!serverless_runtime} ARCH=${ARCH} SLS_ARCH=${SERVERLESS_FRAMEWORK_ARCH} \
            serverless logs --stage ${!run_id} -f $function_name --startTime $script_utc_start_time)
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

            exit 1
        fi

        mkdir -p raw_logs
        PYTHON_VERSION=${!python_version} RUNTIME=$parameters_set SERVERLESS_RUNTIME=${!serverless_runtime} ARCH=${ARCH} SLS_ARCH=${SERVERLESS_FRAMEWORK_ARCH} serverless logs --stage ${!run_id} -f $function_name --startTime $script_utc_start_time > raw_logs/${handler_name}-${parameters_set}.log
        echo '----------------------------------------'
        echo "Raw logs for $function_name with parameters set $parameters_set:"
        echo '----------------------------------------'
        cat raw_logs/${handler_name}-${parameters_set}.log
        echo '----------------------------------------'

        # Replace invocation-specific data like timestamps and IDs with XXXX to normalize logs across executions
        logs=$(
            echo "$raw_logs" |
                node parse-json.js |
                # Filter serverless cli errors
                sed '/Serverless: Recoverable error occurred/d' |
                # Remove RequestsDependencyWarning from botocore/vendored/requests/__init__.py
                sed '/RequestsDependencyWarning/d' |
                # Remove blank lines
                sed '/^$/d' |
                # Normalize Lambda runtime REPORT logs
                sed -E 's/(RequestId|TraceId|SegmentId|Duration|init|Memory Used|"e"): [a-z0-9\.\-]+/\1: XXXX/g' |
                sed -E 's/(python:3.[0-9]+\.v)[0-9]+/\1X/g' |
                # Normalize HTTP headers
                sed -E "s/(x-datadog-parent-id:|x-datadog-trace-id:|Content-Length:)[0-9]+/\1XXXX/g" |
                # Remove Account ID
                sed -E "s/(account_id:)[0-9]+/\1XXXX/g" |
                # Normalize timestamps in datapoints POSTed to DD
                sed -E 's/"points": \[\[[0-9\.]+,/"points": \[\[XXXX,/g' |
                # Strip API key from logged requests
                sed -E "s/(api_key=|'api_key': '|DD-API-KEY:)[a-z0-9\.\-]+/\1XXXX/g" |
                # Normalize package version so that these snapshots aren't broken on version bumps
                sed -E "s/(dd_lambda_layer:datadog-python[0-9]+_)[0-9]+\.[0-9]+\.[0-9]+/\1X\.X\.X/g" |
                sed -E "s/(datadog_lambda:v)([0-9]+\.[0-9]+\.[0-9]+)/\1XX/g" |
                sed -E "s/(datadogpy\/)([0-9]+\.[0-9]+\.[0-9]+)/\1XX/g" |
                sed -E "s/(python )([0-9]\.[0-9]+\.[0-9]+)/\1XX/g" |
                # Strip out run ID (from function name, resource, etc.)
                sed -E "s/${!run_id}/XXXX/g" |
                # Normalize python-requests version
                sed -E "s/(User-Agent:python-requests\/)[0-9]+\.[0-9]+\.[0-9]+/\1X\.X\.X/g" |
                sed -E "s/(\"http.useragent\"\: \"python-requests\/)[0-9]+\.[0-9]+\.[0-9]+/\1X\.X\.X/g" |
                # Strip out trace/span/parent/timestamps
                sed -E "s/(\"trace_id\"\: \")[A-Z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"span_id\"\: \")[A-Z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"parent_id\"\: \")[A-Z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"request_id\"\: \")[a-z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"http.source_ip\"\: \")[a-z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"http.user_agent\"\: \")[a-z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"function_trigger.event_source_arn\"\: \")[A-Za-z0-9\/\.\:\-]+/\1XXXX/g" |
                sed -E "s/(\"duration\"\: )[0-9\.\-]+/\1\"XXXX\"/g" |
                sed -E "s/(\"start\"\: )[0-9\.\-]+/\1\"XXXX\"/g" |
                sed -E "s/(\"system\.pid\"\: )[0-9\.\-]+/\1\"XXXX\"/g" |
                sed -E "s/(\"process_id\"\: )[0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"runtime-id\"\: \")[a-z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/([a-zA-Z0-9]+)(\.execute-api\.[a-z0-9\-]+\.amazonaws\.com)/XXXX\2/g" |
                sed -E "s/(\"apiid\"\: \")[a-z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"apiname\"\: \")[a-z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(\"function_trigger.event_source_arn\"\: \")[a-z0-9\.\-\:]+/\1XXXX/g" |
                sed -E "s/(\"event_id\"\: \")[a-zA-Z0-9\:\-]+/\1XXXX/g" |
                sed -E "s/(\"message_id\"\: \")[a-zA-Z0-9\:\-]+/\1XXXX/g" |
                sed -E "s/(\"request_id\"\:\ \")[a-zA-Z0-9\-\=]+/\1XXXX/g" |
                sed -E "s/(\"connection_id\"\:\ \")[a-zA-Z0-9\-]+/\1XXXX/g" |
                sed -E "s/(\"shardId\-)([0-9]+)\:([a-zA-Z0-9]+)[a-zA-Z0-9]/\1XXXX:XXXX/g" |
                sed -E "s/(\"shardId\-)[0-9a-zA-Z]+/\1XXXX/g" |
                sed -E "s/(\"datadog_lambda\"\: \")([0-9]+\.[0-9]+\.[0-9]+)/\1X.X.X/g" |
                sed -E "s/(\"partition_key\"\:\ \")[a-zA-Z0-9\-]+/\1XXXX/g" |
                sed -E "s/(\"object_etag\"\:\ \")[a-zA-Z0-9\-]+/\1XXXX/g" |
                sed -E "s/(\"dd_trace\"\: \")([0-9]+\.[0-9]+\.[0-9]+)/\1X.X.X/g" |
                sed -E "s/(traceparent\:)([A-Za-z0-9\-]+)/\1XXX/g" |
                sed -E "s/(tracestate\:)([A-Za-z0-9\-\=\:\;].+)/\1XXX/g" |
                sed -E "s/(\"_dd.p.tid\"\: \")[a-z0-9\.\-]+/\1XXXX/g" |
                sed -E "s/(_dd.p.tid=)[a-z0-9\.\-]+/\1XXXX/g" |
                sed -E 's/arch (aarch64|x86_64)/arch XXXX/g' |
                # Parse out account ID in ARN
                sed -E "s/([a-zA-Z0-9]+):([a-zA-Z0-9]+):([a-zA-Z0-9]+):([a-zA-Z0-9\-]+):([a-zA-Z0-9\-\:]+)/\1:\2:\3:\4:XXXX:\4/g" |
                sed -E "/init complete at epoch/d" |
                sed -E "/main started at epoch/d"
        )

        if [ ! -f $function_snapshot_path ]; then
            # If no snapshot file exists yet, we create one
            echo "Writing logs to $function_snapshot_path because no snapshot exists yet"
            echo "$logs" >$function_snapshot_path
        else
            # Compare new logs to snapshots
            diff_output=$(echo "$logs" | sort | diff -w - <(sort $function_snapshot_path))
            if [ $? -eq 1 ]; then
                if [ -n "$UPDATE_SNAPSHOTS" ]; then
                    # If $UPDATE_SNAPSHOTS is set to true write the new logs over the current snapshot
                    echo "Overwriting log snapshot for $function_snapshot_path"
                    echo "$logs" >$function_snapshot_path
                else
                    echo "Failed: Mismatch found between new $function_name logs (first) and snapshot (second):"
                    echo "$diff_output"
                    mismatch_found=true
                fi
            else
                echo "Ok: New logs for $function_name match snapshot"
            fi
        fi
    done
done
set -e

if [ "$mismatch_found" = true ]; then
    echo "FAILURE: A mismatch between new data and a snapshot was found and printed above."
    echo "If the change is expected, generate new snapshots by running 'UPDATE_SNAPSHOTS=true DD_API_KEY=XXXX ./scripts/run_integration_tests.sh'"
    echo "Make sure https://httpstat.us/400/ is UP for 'http_error' test case"
    exit 1
fi

if [ -n "$UPDATE_SNAPSHOTS" ]; then
    echo "SUCCESS: Wrote new snapshots for all functions"
    exit 0
fi

echo "SUCCESS: No difference found between snapshots and new return values or logs"
