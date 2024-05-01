# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2020 Datadog, Inc.

from __future__ import absolute_import
from importlib import import_module

import os
from time import time_ns

from datadog_lambda.tracing import emit_telemetry_on_exception_outside_of_handler
from datadog_lambda.wrapper import datadog_lambda_wrapper
from datadog_lambda.module_name import modify_module_name


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

handler = datadog_lambda_wrapper(handler_func)
