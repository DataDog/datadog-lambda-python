import argparse
import json
import pdb
from pprint import pprint
import sys


LAMBDA_KEYWORD_PREFIXES = ["START", "END", "REPORT", "XRAY"]


def should_keep_log(log_line):
    """Determines if a log line should be kept or ignored

    We want to keep the Lambda keyword log lines and any logs in JSON format, ignore all others
    """
    for prefix in LAMBDA_KEYWORD_PREFIXES:
        if log_line.startswith(prefix):
            return True

    # Keep log lines that are JSON
    try:
        json.loads(log_line)
        return True
    except:
        return False


def parse_args():
    """Parse the function name and logs from the passed args
    """
    parser = argparse.ArgumentParser(description="Compare logs to snapshots")
    parser.add_argument(
        "function_name",
        type=str,
        help="The name of the function whose logs were passed",
    )
    parser.add_argument(
        "logs", type=str, help="The newline-separated logs to compare to snapshot"
    )
    parser.add_argument(
        "--overwrite",
        help="Should the existing snapshot be overwritten with the new logs",
        action="store_true",
    )

    args = parser.parse_args()

    log_lines = [l.strip() for l in args.logs.split("\n") if should_keep_log(l)]

    return args.function_name, log_lines, args.overwrite


def is_trace(log_dict):
    """Checks if the dict has the right keys for representing a trace
    """
    # TODO
    return False


def is_metric(log_dict):
    """Checks if the dict has the keys to represent a metric
    """
    return (
        log_dict.get("e")
        and log_dict.get("m")
        and log_dict.get("t")
        and log_dict.get("v")
    )


def do_metrics_match(log_dict, snapshot_log_dict):
    """Checks if metrics match, ignoring timestamp
    """
    return (
        log_dict.get("m") == snapshot_log_dict.get("m")
        and log_dict.get("t") == snapshot_log_dict.get("t")
        and log_dict.get("v") == snapshot_log_dict.get("v")
    )


def do_log_lines_match(line, snapshot_line):
    """Checks if the line matches the snapshot line, ignoring timestamps and execution IDs
    """
    # Check for the keyword log lines that Lambda generates
    for log_keyword in LAMBDA_KEYWORD_PREFIXES:
        line_starts_with_kw = line.startswith(log_keyword)
        snapshot_line_starts_with_kw = snapshot_line.startswith(log_keyword)

        # If both lines start with the keyword then they match
        if line_starts_with_kw and snapshot_line_starts_with_kw:
            return True

        # If only one line starts with the kw they don't match
        if line_starts_with_kw or snapshot_line_starts_with_kw:
            return False

    try:
        line_dict = json.loads(line)
        snapshot_line_dict = json.loads(snapshot_line)

        if is_metric(line_dict) and is_metric(snapshot_line_dict):
            return do_metrics_match(line_dict, snapshot_line_dict)

    except ValueError:
        # At least one of the lines is neither a keyword line or JSON
        return False

    return False


def do_logsets_match(new_logs, snapshot_logs, function_name):
    """Compare new log lines to the snapshot
    """
    if len(new_logs) != len(snapshot_logs):
        print(
            "Log mismatch for function {}. There are {} lines in the new logs but {} lines in the snapshot:".format(
                function_name, len(new_logs), len(snapshot_logs)
            )
        )
        return False

    for index in range(len(new_logs)):
        if not do_log_lines_match(new_logs[index], snapshot_logs[index]):
            print(
                "Log mismatch for function {}. The log at index {} does not match the snapshot:".format(
                    function_name, index
                )
            )
            print("Snapshot log:\n{}".format(snapshot_logs[index]))
            print("New mismatched log:\n{}".format(new_logs[index]))
            return False

    return True


def get_snapshot_path(function_name):
    """Returns the relative path of the snapshot file
    """
    return "./snapshots/{}.snapshot".format(function_name)


def load_function_snapshot_logs(function_name):
    """Load the specified function's log snapshot
    """
    # TODO return None if the file doesn't exist
    with open(get_snapshot_path(function_name), "r") as f:
        return f.read().split("\n")


def write_snapshot_file(function_name, logs):
    """Create a new snapshot file based on the logs and overwrite the existing snapshot
    """
    # TODO remove any potentially sensitive info from the logs
    with open(get_snapshot_path(function_name), "w") as f:
        f.write("\n".join(logs))


def main():
    function_name, log_lines, should_overwrite = parse_args()
    if should_overwrite:
        print("Overwriting snapshot for {}".format(function_name))
        write_snapshot_file(function_name, log_lines)
        return

    snapshot_logs = load_function_snapshot_logs(function_name)

    logsets_match = do_logsets_match(log_lines, snapshot_logs, function_name)

    if not logsets_match:
        print(
            "Logsets for {} do not match because of errors printed above".format(
                function_name
            )
        )
        print("New logs:")
        pprint(log_lines)
        print("Snapshot logs:")
        pprint(snapshot_logs)
        sys.exit(1)

    print("Newly generated logs for {} match snapshot".format(function_name))


if __name__ == "__main__":
    main()

