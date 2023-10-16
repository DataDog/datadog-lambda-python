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
# RUN find ./python/lib/$runtime/site-packages -name \*.pyc -delete

# Remove botocore (40MB) to reduce package size. aws-xray-sdk
# installs it, while it's already provided by the Lambda Runtime.
RUN find . -type f -name '*.so' -exec chmod +w {} \; -exec strip -g {} \;

WORKDIR /build/python/lib/$runtime/site-packages/ddtrace
RUN find . -type f \( -name '*.c' -o -name '*.cpp' -o -name '*.cc' -o -name '*.h' -o -name '*.hpp' -o -name '*.pyx' \) -delete
RUN python -m compileall .
RUN find . -type f -path "*/__pycache__/*.pyc" | while read pyc_file; do \
  dir_name=$(dirname "$pyc_file") \
  base_name=$(basename "$pyc_file" | sed -E 's/(.*)\..*\..*/\1/') \
  mv "$pyc_file" "$dir_name/../$base_name.pyc"; done
# Remove the empty pycache stuff
RUN find . -type d -name "__pycache__" -empty -delete

# Delete any .py files for which a .pyc exists
RUN find . -type f -name '*.py' | while read py_file; do \
  rm -f "$py_file"; done
WORKDIR /build
RUN rm -rf ./python/lib/$runtime/site-packages/botocore*
RUN rm -rf ./python/lib/$runtime/site-packages/setuptools
RUN rm -rf ./python/lib/$runtime/site-packages/jsonschema/tests
