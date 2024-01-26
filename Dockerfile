ARG image
FROM $image as builder

ARG runtime

# Create the directory structure required for AWS Lambda Layer
RUN mkdir -p /build/python/lib/$runtime/site-packages
WORKDIR /build

# Install datadog_lambda and dependencies from local
COPY . .
RUN pip install . -t ./python/lib/$runtime/site-packages

# Remove *.pyc files
RUN find ./python/lib/$runtime/site-packages -name \*.pyc -delete

# Strip symbols from ddtrace's binaries.
# TODO (AJ): remove when ddtrace fixes this upstream
RUN find . -name '*.so' -exec strip -g {} \;

# Remove botocore (40MB) to reduce package size. aws-xray-sdk
# installs it, while it's already provided by the Lambda Runtime.
RUN rm -rf ./python/lib/$runtime/site-packages/botocore*
RUN rm -rf ./python/lib/$runtime/site-packages/setuptools
RUN rm -rf ./python/lib/$runtime/site-packages/jsonschema/tests

# FROM scratch
# COPY --from=builder /build/python /
