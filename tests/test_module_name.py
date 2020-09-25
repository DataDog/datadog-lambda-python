import sys
import os
import unittest

try:
    from unittest.mock import patch, call, MagicMock
except ImportError:
    from mock import patch, call, MagicMock

from datadog_lambda.module_name import modify_module_name


class TestModifyModuleName(unittest.TestCase):
    def test_modify_module_name(self):
        self.assertEqual(
            modify_module_name("lambda/handler/name.bar"), "lambda.handler.name.bar"
        )
        self.assertEqual(
            modify_module_name("lambda.handler/name.biz"), "lambda.handler.name.biz"
        )
        self.assertEqual(modify_module_name("foo.handler"), "foo.handler")
