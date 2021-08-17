from setuptools import setup
from os import path
from io import open

from datadog_lambda import __version__

here = path.abspath(path.dirname(__file__))

with open(path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="datadog_lambda",
    version=__version__,
    description="The Datadog AWS Lambda Layer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DataDog/datadog-lambda-python",
    author="Datadog, Inc.",
    author_email="dev@datadoghq.com",
    classifiers=[
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    keywords="datadog aws lambda layer",
    packages=["datadog_lambda"],
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*, <4",
    install_requires=[
        "aws-xray-sdk==2.8.0",
        "datadog==0.41.0",
        "ddtrace==0.48.0",
        "wrapt==1.11.2",
        # If building for Python 3, use the latest version of setuptools
        "setuptools>=54.2.0; python_version >= '3.0'",
        # If building for Python 2, use the latest version that supports Python 2
        "setuptools>=44.1.1; python_version < '3.0'",
    ],
    extras_require={
        "dev": ["nose2==0.9.1", "flake8==3.7.9", "requests==2.22.0", "boto3==1.10.33"]
    },
)
