from setuptools import setup
from os import path
from io import open

from datadog_lambda import __version__

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='datadog_lambda',
    version=__version__,
    description='The Datadog AWS Lambda Layer',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/DataDog/datadog-lambda-layer-python',
    author='Datadog, Inc.',
    author_email='dev@datadoghq.com',
    license='Apache 2.0',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    keywords='datadog aws lambda layer',
    packages=['datadog_lambda'],
    python_requires='>=3.6.*, <4',
    install_requires=[
        'aws-xray-sdk==2.4.3',
        'boto3==1.10.46',
        'datadog==0.33.0',
        'ddtrace==0.31.0',
        'wrapt==1.11.2',
        'setuptools==44.0.0',
    ],
    extras_require={
        'dev': [
            'nose2==0.9.1',
            'flake8==3.7.9',
            'requests==2.22.0'
        ]
    }
)
