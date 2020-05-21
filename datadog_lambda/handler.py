from __future__ import absolute_import
from importlib import import_module
import os
from datadog_lambda.wrapper import datadog_lambda_wrapper


class HandlerError(Exception):
    pass


path = os.environ.get("DATADOG_USER_HANDLER", None)
if path is None:
    raise HandlerError(
        "DATADOG_USER_HANDLER is not defined. Can't use prebuilt datadog handler"
    )
parts = path.rsplit(".", 1)
if len(parts) != 2:
    raise HandlerError("Value %s for DATADOG_USER_HANDLER has invalid format." % path)

(mod_name, handler_name) = parts
handler_module = import_module(mod_name)
handler = datadog_lambda_wrapper(getattr(handler_module, handler_name))
