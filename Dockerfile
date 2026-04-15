ARG image
FROM $image as builder

ARG runtime

# Create the directory structure required for AWS Lambda Layer
RUN mkdir -p /build/python/lib/$runtime/site-packages
WORKDIR /build

# Install newer version of GCC on AL2
RUN set -eux; \
    if command -v yum >/dev/null 2>&1; then \
      yum -y install git gcc10 gcc10-c++; \
      cd /usr/bin; \
      rm gcc && ln -s gcc10-gcc gcc; \
      rm g++ && ln -s gcc10-g++ g++; \
      rm cc && ln -s gcc10-cc cc; \
      rm c++ && ln -s gcc10-c++ c++; \
    fi

# Add Rust compiler which is needed to build dd-trace-py from source
RUN curl https://sh.rustup.rs -sSf | \
    sh -s -- --default-toolchain stable -y
ENV PATH=/root/.cargo/bin:$PATH

# Install datadog_lambda and dependencies from local
COPY . .

RUN pip install --no-cache-dir . -t ./python/lib/$runtime/site-packages

# Remove botocore (40MB) to reduce package size. aws-xray-sdk
# installs it, while it's already provided by the Lambda Runtime.
RUN rm -rf ./python/lib/$runtime/site-packages/botocore*
RUN rm -rf ./python/lib/$runtime/site-packages/setuptools
RUN rm -rf ./python/lib/$runtime/site-packages/jsonschema/tests

# Remove unsupported appsec modules
RUN rm -rf \
    ./python/lib/$runtime/site-packages/ddtrace/appsec/_iast \
    ./python/lib/$runtime/site-packages/ddtrace/appsec/sca \
    ./python/lib/$runtime/site-packages/ddtrace/appsec/_shared

# CI Visibility paths/integrations
RUN rm -rf \
    ./python/lib/$runtime/site-packages/ddtrace/contrib/coverage/ \
    ./python/lib/$runtime/site-packages/ddtrace/contrib/pytest/ \
    ./python/lib/$runtime/site-packages/ddtrace/contrib/pytest_bdd/ \
    ./python/lib/$runtime/site-packages/ddtrace/contrib/pytest_benchmark/ \
    ./python/lib/$runtime/site-packages/ddtrace/contrib/selenium/ \
    ./python/lib/$runtime/site-packages/ddtrace/contrib/unittest/ \
    ./python/lib/$runtime/site-packages/ddtrace/ext/ci_visibility \
    ./python/lib/$runtime/site-packages/ddtrace/ext/test_visibility \
    ./python/lib/$runtime/site-packages/ddtrace/internal/ci_visibility \
    ./python/lib/$runtime/site-packages/ddtrace/internal/coverage \
    ./python/lib/$runtime/site-packages/ddtrace/internal/test_visibility \
    ./python/lib/$runtime/site-packages/ddtrace/testing/

# Dogshell
RUN rm -rf ./python/lib/$runtime/site-packages/datadog/dogshell
RUN rm -rf ./python/lib/$runtime/site-packages/bin/dog*

# remove *.dist-info directories except any entry_points.txt files and METADATA files required for Appsec Software Composition Analysis
RUN find ./python/lib/$runtime/site-packages/*.dist-info \
        -type f \
        ! \( -name 'entry_points.txt' -o -name 'METADATA' \) \
        -delete
RUN find ./python/lib/$runtime/site-packages -type d -empty -delete

# Remove requests and dependencies
RUN rm -rf \
        ./python/lib/$runtime/site-packages/requests* \
        ./python/lib/$runtime/site-packages/urllib3* \
        ./python/lib/$runtime/site-packages/certifi* \
        ./python/lib/$runtime/site-packages/idna* \
        ./python/lib/$runtime/site-packages/charset_normalizer* \
        ./python/lib/$runtime/site-packages/*__mypyc*.so  # from charset_normalizer

# Precompile all .pyc files and remove .py files. This speeds up load time.
# Compile with optimization level 2 (-OO) and PYTHONNODEBUGRANGES=1 to redtce
# size of .pyc files.
# See https://docs.python.org/3/tutorial/modules.html#compiled-python-files
# https://docs.python.org/3.11/using/cmdline.html#cmdoption-O
# https://docs.python.org/3/using/cmdline.html#envvar-PYTHONNODEBUGRANGES
RUN PYTHONNODEBUGRANGES=1 python -OO -m compileall -b ./python/lib/$runtime/site-packages
# remove all .py files
# DEV: ddtrace>=4.7.0rc3 checks for .pyc files in addition to .py files for instrumentation
# discovery (DataDog/dd-trace-py#17196), so we can safely remove all .py files.
# For older versions, we need to keep patch.py files for instrumentation discovery.
RUN pip install --quiet packaging && \
    DDTRACE_VERSION=$(grep "^Version:" ./python/lib/$runtime/site-packages/ddtrace-*.dist-info/METADATA | awk '{print $2}') && \
    if python -c "from packaging.version import Version; exit(0 if Version('$DDTRACE_VERSION') >= Version('4.7.0rc3') else 1)"; then \
        find ./python/lib/$runtime/site-packages -name \*.py | xargs rm -rf; \
    else \
        find ./python/lib/$runtime/site-packages -name \*.py | grep -v ddtrace/contrib | xargs rm -rf && \
        find ./python/lib/$runtime/site-packages/ddtrace/contrib -name \*.py | grep -v patch.py | xargs rm -rf; \
    fi
RUN find ./python/lib/$runtime/site-packages -name __pycache__ -type d -exec rm -r {} \+

# When building ddtrace from branch, remove extra source files.  These are
# removed by the ddtrace build process before publishing a wheel to PyPI.
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.c -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.cpp -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.cc -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.h -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.hpp -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.pyx -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.pyi -delete

# Strip debug symbols and symbols that are not needed for relocation
# processing  using strip --strip-unneeded for all .so files. This is to
# reduce the size when ddtrace is built from sources. The release wheels are
# already stripped of debug symbols. We should revisit this when serverless
# benchmark uses pre-built wheels instead of building from sources.
RUN find ./python/lib/$runtime/site-packages -name "*.so" -exec strip --strip-unneeded {} \;

FROM scratch
COPY --from=builder /build/python /
