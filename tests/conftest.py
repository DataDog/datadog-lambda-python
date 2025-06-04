import pytest

from datadog_lambda.config import config


@pytest.fixture(autouse=True)
def reset_config():
    config._reset()
