ARG image
FROM $image

ARG runtime

# Create the directory structure required for AWS Lambda Layer
RUN mkdir -p /build/python/lib/$runtime/site-packages
WORKDIR /build

# Install datadog_lambda and dependencies from local
COPY . .
RUN pip install . -t ./python/lib/$runtime/site-packages

# Remove *.pyc files
RUN find ./python/lib/$runtime/site-packages -name \*.pyc -delete