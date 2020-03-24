ARG python_version
FROM python:$python_version

ENV PYTHONDONTWRITEBYTECODE True

RUN mkdir -p /test
WORKDIR /test

# Install datadog-lambda with dev dependencies from local
COPY . .
RUN pip install .[dev]
RUN pip install --find-links=https://s3.amazonaws.com/pypi.datadoghq.com/trace-dev/index.html ddtrace==0.35.1.dev5+g1e11b2dd -t .[dev]
