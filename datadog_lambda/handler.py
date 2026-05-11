# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2020 Datadog, Inc.

from importlib import import_module

import json
import os
from time import time_ns


# Initialize Live Debugger.
#
# Two modes:
#   v2 (extension-native RC): DD_LIVE_DEBUGGER_ENABLED=true
#       The extension's RC poller writes probes to /tmp/live-debugger-probes.json.
#       We just point ddtrace at that file and enable DI.
#   v1 (remote instrumenter): DD_LIVE_DEBUGGER_CONFIG_PARAM or DD_LIVE_DEBUGGER_CONFIG
#       Probes delivered via SSM parameter or env var (set by instrumenter Lambda).
#       We read JSON, normalize paths, write to /tmp, and enable DI.
#
# Must run BEFORE ddtrace is imported.
def _initialize_live_debugger():
    probe_file = "/tmp/live-debugger-probes.json"

    # --- v2 mode: extension delivers probes via file ---
    if os.environ.get("DD_LIVE_DEBUGGER_ENABLED", "").lower() == "true":
        os.environ["DD_DYNAMIC_INSTRUMENTATION_PROBE_FILE"] = probe_file
        os.environ["DD_DYNAMIC_INSTRUMENTATION_ENABLED"] = "true"
        print(f"[LIVE_DEBUGGER] v2 mode: extension RC poller delivers probes to {probe_file}")
        print(f"[LIVE_DEBUGGER] DD_DYNAMIC_INSTRUMENTATION_ENABLED=true")
        return

    # --- v1 mode: probes from SSM or env var ---
    config_json = None

    param_name = os.environ.get("DD_LIVE_DEBUGGER_CONFIG_PARAM")
    if param_name:
        try:
            import boto3
            import time as _time
            ssm = boto3.client("ssm", region_name=os.environ.get("AWS_REGION", "us-east-1"))
            _t0 = _time.monotonic()
            config_json = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
            _ms = int((_time.monotonic() - _t0) * 1000)
            print(f"[LIVE_DEBUGGER] Loaded config from SSM {param_name!r} in {_ms}ms")
        except Exception as e:
            print(f"[LIVE_DEBUGGER] Failed to load from SSM {param_name!r}: {e}")

    if not config_json:
        config_json = os.environ.get("DD_LIVE_DEBUGGER_CONFIG")

    if not config_json:
        print("[LIVE_DEBUGGER] No live debugger config found, skipping")
        return
    try:
        probes = json.loads(config_json)
        # Normalize sourceFile: strip /var/task/ prefix so dd-trace-py can
        # match the module by relative path (e.g. "live-debugger-handler.py")
        for probe in probes:
            where = probe.get("where") or {}
            src = where.get("sourceFile", "")
            if src.startswith("/var/task/"):
                where["sourceFile"] = src[len("/var/task/"):]
        config_json = json.dumps(probes)
        with open(probe_file, "w") as f:
            f.write(config_json)
        os.environ["DD_DYNAMIC_INSTRUMENTATION_PROBE_FILE"] = probe_file
        os.environ["DD_DYNAMIC_INSTRUMENTATION_ENABLED"] = "true"
        print(f"[LIVE_DEBUGGER] Initialized {len(probes)} probe(s), probe_file={probe_file}")
        print(f"[LIVE_DEBUGGER] DD_DYNAMIC_INSTRUMENTATION_ENABLED=true")
    except Exception as e:
        print(f"[LIVE_DEBUGGER] Failed to initialize: {e}")


_initialize_live_debugger()

from datadog_lambda.tracing import emit_telemetry_on_exception_outside_of_handler
from datadog_lambda.wrapper import datadog_lambda_wrapper
from datadog_lambda.module_name import modify_module_name

# Explicitly enable DynamicInstrumentation after ddtrace is imported.
# In Lambda, ddtrace-run is NOT used, so the product manager never starts,
# meaning DD_DYNAMIC_INSTRUMENTATION_ENABLED alone is not enough.
def _start_dynamic_instrumentation():
    has_v2 = os.environ.get("DD_LIVE_DEBUGGER_ENABLED", "").lower() == "true"
    has_v1 = bool(os.environ.get("DD_LIVE_DEBUGGER_CONFIG") or os.environ.get("DD_LIVE_DEBUGGER_CONFIG_PARAM"))
    if not has_v2 and not has_v1:
        return
    try:
        from ddtrace.debugging import DynamicInstrumentation
        DynamicInstrumentation.enable()
        print("[LIVE_DEBUGGER] DynamicInstrumentation.enable() called")
    except Exception as e:
        print(f"[LIVE_DEBUGGER] Failed to enable DynamicInstrumentation: {e}")

_start_dynamic_instrumentation()


# Explicitly bootstrap SymbolDatabase after ddtrace is imported.
# In Lambda, ddtrace-run is NOT used, so the product manager never starts,
# meaning DD_SYMBOL_DATABASE_FORCE_UPLOAD alone is not enough.
def _start_symbol_database():
    if not os.environ.get("DD_SYMBOL_DATABASE_FORCE_UPLOAD"):
        return
    try:
        from ddtrace.internal.settings.symbol_db import config as symdb_config
        symdb_config._force = True
        from ddtrace.internal.symbol_db.symbols import SymbolDatabaseUploader
        SymbolDatabaseUploader.install()
        print(f"[LIVE_DEBUGGER] symbol_db.bootstrap() called, is_installed={SymbolDatabaseUploader.is_installed()}")
    except Exception as e:
        print(f"[LIVE_DEBUGGER] Failed to bootstrap symbol_db: {e}")

_start_symbol_database()


class HandlerError(Exception):
    pass


path = os.environ.get("DD_LAMBDA_HANDLER", None)
if path is None:
    raise HandlerError(
        "DD_LAMBDA_HANDLER is not defined. Can't use prebuilt datadog handler"
    )
parts = path.rsplit(".", 1)
if len(parts) != 2:
    raise HandlerError(f"Value {path} for DD_LAMBDA_HANDLER has invalid format.")


(mod_name, handler_name) = parts
modified_mod_name = modify_module_name(mod_name)

try:
    handler_load_start_time_ns = time_ns()
    handler_module = import_module(modified_mod_name)
    handler_func = getattr(handler_module, handler_name)
except Exception as e:
    emit_telemetry_on_exception_outside_of_handler(
        e,
        modified_mod_name,
        handler_load_start_time_ns,
    )
    raise

# --- v2 probe file change detection ---
# On warm invocations, the extension's RC poller may write new probes to
# /tmp/live-debugger-probes.json between invocations.  We track the file's
# mtime and, when it changes, tell ddtrace's Debugger to re-read the file
# so new debug sessions / probe changes take effect without a cold start.
_probe_file_path = "/tmp/live-debugger-probes.json"
_last_probe_mtime = None


def _check_probe_file_changes():
    """Re-load probe config if the file has been updated since last check."""
    global _last_probe_mtime

    if os.environ.get("DD_LIVE_DEBUGGER_ENABLED", "").lower() != "true":
        return

    try:
        mtime = os.path.getmtime(_probe_file_path)
    except OSError:
        # File doesn't exist (yet) -- nothing to do
        return

    if _last_probe_mtime is not None and mtime == _last_probe_mtime:
        return  # unchanged

    _last_probe_mtime = mtime

    try:
        import time as _time
        from ddtrace.debugging._debugger import Debugger

        debugger = Debugger._instance
        if debugger is None:
            return
        _t0 = _time.monotonic()
        debugger._load_local_config()
        _ms = int((_time.monotonic() - _t0) * 1000)
        print("[LIVE_DEBUGGER] Probe file changed, reloaded probes from %s (%dms)" % (_probe_file_path, _ms))
    except Exception as e:
        print("[LIVE_DEBUGGER] Failed to reload probes: %s" % e)


_wrapped_handler = datadog_lambda_wrapper(handler_func)


def handler(event, context, **kwargs):
    _check_probe_file_changes()
    return _wrapped_handler(event, context, **kwargs)
