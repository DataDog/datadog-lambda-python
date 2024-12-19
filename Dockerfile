ARG image
FROM $image as builder

ARG runtime

# Create the directory structure required for AWS Lambda Layer
RUN mkdir -p /build/python/lib/$runtime/site-packages
WORKDIR /build

# Add Rust compiler which is needed to build dd-trace-py from source
RUN curl https://sh.rustup.rs -sSf | \
    sh -s -- --default-toolchain stable -y
ENV PATH=/root/.cargo/bin:$PATH

# Install datadog_lambda and dependencies from local
COPY . .
RUN pip install . -t ./python/lib/$runtime/site-packages

# Remove botocore (40MB) to reduce package size. aws-xray-sdk
# installs it, while it's already provided by the Lambda Runtime.
RUN rm -rf ./python/lib/$runtime/site-packages/botocore*
RUN rm -rf ./python/lib/$runtime/site-packages/setuptools
RUN rm -rf ./python/lib/$runtime/site-packages/jsonschema/tests
RUN find . -name 'libddwaf.so' -delete
RUN rm -rf ./python/lib/$runtime/site-packages/urllib3*
RUN rm ./python/lib/$runtime/site-packages/ddtrace/appsec/_iast/_taint_tracking/*.so
RUN rm ./python/lib/$runtime/site-packages/ddtrace/appsec/_iast/_stacktrace*.so
RUN rm ./python/lib/$runtime/site-packages/ddtrace/internal/datadog/profiling/libdd_wrapper*.so
RUN rm ./python/lib/$runtime/site-packages/ddtrace/internal/datadog/profiling/ddup/_ddup.*.so
RUN rm ./python/lib/$runtime/site-packages/ddtrace/internal/datadog/profiling/stack_v2/_stack_v2.*.so
RUN find . -name "*.dist-info" -type d | xargs rm -rf

# The requests package is available in the lambda runtime already as
# pip._vendor.requests.  Before importing requests, `/path/to/pip/_vendor` must
# be added to `sys.path`.
RUN rm -rf \
        ./python/lib/$runtime/site-packages/requests* \
        ./python/lib/$runtime/site-packages/certifi* \
        ./python/lib/$runtime/site-packages/idna* \
        ./python/lib/$runtime/site-packages/charset_normalizer*

# Precompile all .pyc files and remove .py files. This speeds up load time.
# Compile with optimization level 2 (-OO) and PYTHONNODEBUGRANGES=1 to redtce
# size of .pyc files.
# See https://docs.python.org/3/tutorial/modules.html#compiled-python-files
# https://docs.python.org/3.11/using/cmdline.html#cmdoption-O
# https://docs.python.org/3/using/cmdline.html#envvar-PYTHONNODEBUGRANGES
RUN PYTHONNODEBUGRANGES=1 python -OO -m compileall -b ./python/lib/$runtime/site-packages
# remove all .py files except ddtrace/contrib/*/__init__.py which are necessary
# for ddtrace.patch to discover instrumationation packages.
RUN find ./python/lib/$runtime/site-packages -name \*.py | grep -v ddtrace/contrib | xargs rm -rf
RUN find ./python/lib/$runtime/site-packages/ddtrace/contrib -name \*.py | grep -v __init__ | xargs rm -rf
RUN find ./python/lib/$runtime/site-packages -name __pycache__ -type d -exec rm -r {} \+

# When building ddtrace from branch, remove extra source files.  These are
# removed by the ddtrace build process before publishing a wheel to PyPI.
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.c -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.cpp -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.cc -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.h -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.hpp -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.pyx -delete

FROM scratch
COPY --from=builder /build/python /
