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

# Remove botocore (40MB) to reduce package size. aws-xray-sdk
# installs it, while it's already provided by the Lambda Runtime.
RUN rm -rf ./python/lib/$runtime/site-packages/botocore*

# Remove profiling (7MB) to reduce package size.
# Continous profiling is not yet supported anyway.
# RUN rm -rf ./python/lib/$runtime/site-packages/ddtrace/profiling
COPY ./ddtrace ./python/lib/$runtime/site-packages/ddtrace