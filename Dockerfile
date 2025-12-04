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
RUN rm -f ./python/lib/$runtime/site-packages/ddtrace/appsec/_iast/_ast/iastpatch*.so
RUN rm -rf ./python/lib/$runtime/site-packages/ddtrace/appsec/_iast/_taint_tracking/_vendor
RUN rm -f ./python/lib/$runtime/site-packages/ddtrace/appsec/_iast/_taint_tracking/*.so
RUN rm -f ./python/lib/$runtime/site-packages/ddtrace/appsec/_iast/_stacktrace*.so
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
        ./python/lib/$runtime/site-packages/charset_normalizer*

# Precompile all .pyc files and remove .py files. This speeds up load time.
# Compile with optimization level 2 (-OO) and PYTHONNODEBUGRANGES=1 to redtce
# size of .pyc files.
# See https://docs.python.org/3/tutorial/modules.html#compiled-python-files
# https://docs.python.org/3.11/using/cmdline.html#cmdoption-O
# https://docs.python.org/3/using/cmdline.html#envvar-PYTHONNODEBUGRANGES
RUN PYTHONNODEBUGRANGES=1 python -OO -m compileall -b ./python/lib/$runtime/site-packages
# remove all .py files except ddtrace/contrib/*/patch.py which are necessary
# for ddtrace.patch to discover instrumationation packages.
RUN find ./python/lib/$runtime/site-packages -name \*.py | grep -v ddtrace/contrib | xargs rm -rf
RUN find ./python/lib/$runtime/site-packages/ddtrace/contrib -name \*.py | grep -v patch.py | xargs rm -rf
RUN find ./python/lib/$runtime/site-packages -name __pycache__ -type d -exec rm -r {} \+

# When building ddtrace from branch, remove extra source files.  These are
# removed by the ddtrace build process before publishing a wheel to PyPI.
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.c -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.cpp -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.cc -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.h -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.hpp -delete
RUN find ./python/lib/$runtime/site-packages/ddtrace -name \*.pyx -delete

# Strip debug symbols and symbols that are not needed for relocation
# processing  using strip --strip-unneeded for all .so files. This is to
# reduce the size when ddtrace is built from sources. The release wheels are
# already stripped of debug symbols. We should revisit this when serverless
# benchmark uses pre-built wheels instead of building from sources.
RUN find ./python/lib/$runtime/site-packages -name "*.so" -exec strip --strip-unneeded {} \;

FROM scratch
COPY --from=builder /build/python /
