import importlib.metadata
from datadog_lambda import __version__


def test_version():
    # test version in __init__ matches version in pyproject.toml
    assert importlib.metadata.version("datadog-lambda") == __version__
