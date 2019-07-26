ARG python_version
FROM python:$python_version

ENV PYTHONDONTWRITEBYTECODE True

RUN mkdir -p /test
WORKDIR /test

# Install datadog-lambda with dev dependencies from local
COPY . .
RUN pip install .[dev]