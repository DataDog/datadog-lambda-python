ARG python_version
FROM python:$python_version

ENV PYTHONDONTWRITEBYTECODE True

RUN mkdir -p /test/datadog_lambda
WORKDIR /test

# Copy minimal subset of files to make pip install succeed and be cached (next docker builds will be way faster)
COPY pyproject.toml .
COPY poetry.lock .
COPY README.md .
COPY datadog_lambda/__init__.py datadog_lambda/__init__.py 

RUN pip install .[dev]

# Install datadog-lambda with dev dependencies from local
COPY . .
