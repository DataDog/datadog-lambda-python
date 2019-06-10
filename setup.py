from setuptools import setup
from os import path
from io import open

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='ddlambda',
    version='0.2.0',
    description='The Datadog AWS Lambda Layer',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/DataDog/datadog-lambda-layer-python',
    author='Datadog, Inc.',
    author_email='dev@datadoghq.com',
    classifiers=[
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords='datadog aws lambda layer',
    packages=['datadog_lambda'],
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*, <4',
)
