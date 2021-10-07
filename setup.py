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
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    keywords="datadog aws lambda layer",
    packages=["datadog_lambda"],
    python_requires=">=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*, <4",
    install_requires=[
        "datadog==0.41.0",
        "ddtrace==0.53.0",
        "wrapt==1.11.2",
        "setuptools>=54.2.0; python_version >= '3.0'",
    ],
    extras_require={
        "dev": [
            "nose2==0.9.1",
            "flake8==3.7.9",
            "requests==2.22.0",
            "boto3==1.10.33",
            "httpretty==0.9.7",
        ]
    },
)
