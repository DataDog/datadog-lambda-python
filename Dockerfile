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
RUN find ./python/lib/$runtime/site-packages -name \*.pyc -exec rm -rfv {} \;

# Remove botocore (40MB) to reduce package size. aws-xray-sdk
# installs it, while it's already provided by the Lambda Runtime.
RUN rm -rf ./python/lib/$runtime/site-packages/botocore*
RUN rm -rf ./python/lib/$runtime/site-packages/setuptools
RUN rm -rf ./python/lib/$runtime/site-packages/jsonschema/tests
RUN find . -name 'libddwaf.so' -delete
RUN rm -rf ./python/lib/$runtime/site-packages/urllib3
RUN rm ./python/lib/$runtime/site-packages/ddtrace/appsec/_iast/_taint_tracking/*.so
RUN rm ./python/lib/$runtime/site-packages/ddtrace/appsec/_iast/_stacktrace*.so
RUN rm ./python/lib/$runtime/site-packages/ddtrace/internal/datadog/profiling/libdd_wrapper.so
RUN rm ./python/lib/$runtime/site-packages/ddtrace/internal/datadog/profiling/ddup/_ddup.*.so
RUN rm ./python/lib/$runtime/site-packages/ddtrace/internal/datadog/profiling/stack_v2/_stack_v2.*.so

FROM scratch
COPY --from=builder /build/python /
