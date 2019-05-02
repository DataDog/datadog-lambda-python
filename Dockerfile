ARG image
FROM $image

ARG runtime

# Create the directory structure required for AWS Lambda Layer
RUN mkdir -p /build/python/lib/$runtime/site-packages
WORKDIR /build

# Install dependencies
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt -t ./python/lib/$runtime/site-packages

# Install datadog_lambda
COPY datadog_lambda ./python/lib/$runtime/site-packages

# Remove *.pyc files
RUN find ./python/lib/$runtime/site-packages -name \*.pyc -delete