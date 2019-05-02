ARG python_version
FROM python:$python_version

ENV PYTHONDONTWRITEBYTECODE True

COPY requirements.txt requirements.txt
COPY requirements-dev.txt requirements-dev.txt
RUN pip install -r requirements.txt
RUN pip install -r requirements-dev.txt