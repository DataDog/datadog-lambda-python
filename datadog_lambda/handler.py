# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https://www.datadoghq.com/).
# Copyright 2020 Datadog, Inc.

from __future__ import absolute_import
from importlib import import_module

import os
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
    raise HandlerError("Value %s for DD_LAMBDA_HANDLER has invalid format." % path)

(mod_name, handler_name) = parts
modified_mod_name = modify_module_name(mod_name)
handler_module = import_module(modified_mod_name)
handler = datadog_lambda_wrapper(getattr(handler_module, handler_name))
