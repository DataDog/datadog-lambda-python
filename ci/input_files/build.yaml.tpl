{{- $e2e_region := "us-west-2" -}}

stages:
 - build
 - test
 - sign
 - publish
 - e2e

.python-before-script: &python-before-script
  - pip install virtualenv
  - virtualenv venv
  - source venv/bin/activate
  - pip install .[dev]
  - pip install poetry

default:
  retry:
    max: 1
    when:
      # Retry when the runner fails to start
      - runner_system_failure

# This is for serverless framework
.install-node: &install-node
  - apt-get update
  - apt-get install -y ca-certificates curl gnupg xxd
  - mkdir -p /etc/apt/keyrings
  - curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
  # We are explicitly setting the node_20.x version for the installation
  - echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
  - apt-get update
  - apt-get install nodejs -y
  - npm install --global yarn

{{ range $runtime := (ds "runtimes").runtimes }}

# TODO(astuyve) - figure out python build cache
.{{ $runtime.name }}-{{ $runtime.arch }}-cache: &{{ $runtime.name }}-{{ $runtime.arch }}-cache
  key: "$CI_JOB_STAGE-$CI_COMMIT_REF_SLUG"
  paths:
    - $CI_PROJECT_DIR/.yarn-cache
  policy: pull

build-layer ({{ $runtime.name }}-{{ $runtime.arch }}):
  stage: build
  tags: ["arch:amd64"]
  image: registry.ddbuild.io/images/docker:20.10
  artifacts:
    expire_in: 1 hr # Unsigned zips expire in 1 hour
    paths:
      - .layers/datadog_lambda_py-{{ $runtime.arch }}-{{ $runtime.python_version }}.zip
  variables:
    CI_ENABLE_CONTAINER_IMAGE_BUILDS: "true"
  script:
    - PYTHON_VERSION={{ $runtime.python_version }} ARCH={{ $runtime.arch }} ./scripts/build_layers.sh
  retry: 2

check-layer-size ({{ $runtime.name }}-{{ $runtime.arch }}):
  stage: test
  tags: ["arch:amd64"]
  image: registry.ddbuild.io/images/docker:20.10
  needs:
    - build-layer ({{ $runtime.name }}-{{ $runtime.arch }})
  dependencies:
    - build-layer ({{ $runtime.name }}-{{ $runtime.arch }})
  script:
    - PYTHON_VERSION={{ $runtime.python_version }} ARCH={{ $runtime.arch }} ./scripts/check_layer_size.sh

lint python:
  stage: test
  tags: ["arch:amd64"]
  image: registry.ddbuild.io/images/mirror/python:{{ $runtime.image }}
  cache: &{{ $runtime.name }}-{{ $runtime.arch }}-cache
  before_script: *python-before-script
  script:
    - source venv/bin/activate
    - ./scripts/check_format.sh

unit-test ({{ $runtime.name }}-{{ $runtime.arch }}):
  stage: test
  tags: ["arch:amd64"]
  image: registry.ddbuild.io/images/mirror/python:{{ $runtime.image }}
  cache: &{{ $runtime.name }}-{{ $runtime.arch }}-cache
  before_script: *python-before-script
  script:
    - source venv/bin/activate
    - pytest -vv
  retry: 2

integration-test ({{ $runtime.name }}-{{ $runtime.arch }}):
  stage: test
  tags: ["arch:amd64"]
  image: registry.ddbuild.io/images/docker:20.10-py3
  rules:
    - if: '$SKIP_E2E_TESTS == "true"'
      when: never
    - when: on_success
  needs:
    - build-layer ({{ $runtime.name }}-{{ $runtime.arch }})
  dependencies:
    - build-layer ({{ $runtime.name }}-{{ $runtime.arch }})
  cache: &{{ $runtime.name }}-{{ $runtime.arch }}-cache
  variables:
    CI_ENABLE_CONTAINER_IMAGE_BUILDS: "true"
  before_script:
    - *install-node
    - EXTERNAL_ID_NAME=integration-test-externalid ROLE_TO_ASSUME=sandbox-integration-test-deployer AWS_ACCOUNT=425362996713 source ./ci/get_secrets.sh
    - yarn global add serverless@^3.38.0 --prefix /usr/local
    - yarn global add serverless-python-requirements@^6.1.1 --prefix /usr/local
    - cd integration_tests && yarn install && cd ..
  script:
    - RUNTIME_PARAM={{ $runtime.python_version }} ARCH={{ $runtime.arch }} ./scripts/run_integration_tests.sh
  retry: 2

sign-layer ({{ $runtime.name }}-{{ $runtime.arch }}):
  stage: sign
  tags: ["arch:amd64"]
  image: registry.ddbuild.io/images/docker:20.10-py3
  rules:
    - if: '$CI_COMMIT_TAG =~ /^v.*/'
      when: manual
  needs:
    - build-layer ({{ $runtime.name }}-{{ $runtime.arch }})
    - check-layer-size ({{ $runtime.name }}-{{ $runtime.arch }})
    - lint python
    - unit-test ({{ $runtime.name }}-{{ $runtime.arch }})
    - integration-test ({{ $runtime.name }}-{{ $runtime.arch }})
  dependencies:
    - build-layer ({{ $runtime.name }}-{{ $runtime.arch }})
  artifacts: # Re specify artifacts so the modified signed file is passed
    expire_in: 1 day # Signed layers should expire after 1 day
    paths:
      - .layers/datadog_lambda_py-{{ $runtime.arch }}-{{ $runtime.python_version }}.zip
  before_script:
    - apt-get update
    - apt-get install -y uuid-runtime
    {{ with $environment := (ds "environments").environments.prod }}
    - EXTERNAL_ID_NAME={{ $environment.external_id }} ROLE_TO_ASSUME={{ $environment.role_to_assume }} AWS_ACCOUNT={{ $environment.account }} source ./ci/get_secrets.sh
    {{ end }}
  script:
    - LAYER_FILE=datadog_lambda_py-{{ $runtime.arch}}-{{ $runtime.python_version }}.zip ./scripts/sign_layers.sh prod

{{ range $environment_name, $environment := (ds "environments").environments }}
{{ $dotenv := print $runtime.name "_" $runtime.arch "_" $environment_name ".env" }}

publish-layer-{{ $environment_name }} ({{ $runtime.name }}-{{ $runtime.arch }}):
  stage: publish
  tags: ["arch:amd64"]
  image: registry.ddbuild.io/images/docker:20.10-py3
  rules:
    - if: '$SKIP_E2E_TESTS == "true"'
      when: never
    - if: '"{{ $environment_name }}" == "sandbox" && $REGION == "{{ $e2e_region }}" && "{{ $runtime.arch }}" == "amd64"'
      when: on_success
    - if: '"{{ $environment_name }}" == "sandbox"'
      when: manual
      allow_failure: true
    - if: '$CI_COMMIT_TAG =~ /^v.*/'
  artifacts:
    reports:
      dotenv: {{ $dotenv }}
  needs:
{{ if or (eq $environment_name "prod") }}
      - sign-layer ({{ $runtime.name }}-{{ $runtime.arch}})
{{ else }}
      - build-layer ({{ $runtime.name }}-{{ $runtime.arch }})
      - check-layer-size ({{ $runtime.name }}-{{ $runtime.arch }})
      - lint python
      - unit-test ({{ $runtime.name }}-{{ $runtime.arch }})
      - integration-test ({{ $runtime.name }}-{{ $runtime.arch }})
{{ end }}
  dependencies:
{{ if or (eq $environment_name "prod") }}
      - sign-layer ({{ $runtime.name }}-{{ $runtime.arch}})
{{ else }}
      - build-layer ({{ $runtime.name }}-{{ $runtime.arch }})
{{ end }}
  parallel:
    matrix:
      - REGION: {{ range (ds "regions").regions }}
          - {{ .code }}
        {{- end}}
  before_script:
    - EXTERNAL_ID_NAME={{ $environment.external_id }} ROLE_TO_ASSUME={{ $environment.role_to_assume }} AWS_ACCOUNT={{ $environment.account }} source ./ci/get_secrets.sh
  script:
    - STAGE={{ $environment_name }} PYTHON_VERSION={{ $runtime.python_version }} ARCH={{ $runtime.arch }} DOTENV={{ $dotenv }} ./ci/publish_layers.sh

{{- end }}

{{- end }}

publish-pypi-package:
  stage: publish
  tags: ["arch:amd64"]
  image: registry.ddbuild.io/images/docker:20.10-py3
  before_script: *python-before-script
  cache: []
  rules:
    - if: '$CI_COMMIT_TAG =~ /^v.*/'
  when: manual
  needs: {{ range $runtime := (ds "runtimes").runtimes }}
    - sign-layer ({{ $runtime.name }}-{{ $runtime.arch}})
  {{- end }}
  script:
    - ./ci/publish_pypi.sh

layer bundle:
  stage: build
  tags: ["arch:amd64"]
  image: registry.ddbuild.io/images/docker:20.10
  needs:
    {{ range (ds "runtimes").runtimes }}
    - build-layer ({{ .name }}-{{ .arch }})
    {{ end }}
  dependencies:
    {{ range (ds "runtimes").runtimes }}
    - build-layer ({{ .name }}-{{ .arch }})
    {{ end }}
  artifacts:
    expire_in: 1 hr
    paths:
      - datadog_lambda_py-bundle-${CI_JOB_ID}/
    name: datadog_lambda_py-bundle-${CI_JOB_ID}
  script:
    - rm -rf datadog_lambda_py-bundle-${CI_JOB_ID}
    - mkdir -p datadog_lambda_py-bundle-${CI_JOB_ID}
    - cp .layers/datadog_lambda_py-*.zip datadog_lambda_py-bundle-${CI_JOB_ID}

signed layer bundle:
  stage: sign
  image: registry.ddbuild.io/images/docker:20.10-py3
  tags: ["arch:amd64"]
  rules:
    - if: '$CI_COMMIT_TAG =~ /^v.*/'
  needs:
    {{ range (ds "runtimes").runtimes }}
    - sign-layer ({{ .name }}-{{ .arch }})
    {{ end }}
  dependencies:
    {{ range (ds "runtimes").runtimes }}
    - sign-layer ({{ .name }}-{{ .arch }})
    {{ end }}
  artifacts:
    expire_in: 1 day
    paths:
      - datadog_lambda_py-signed-bundle-${CI_JOB_ID}/
    name: datadog_lambda_py-signed-bundle-${CI_JOB_ID}
  script:
    - rm -rf datadog_lambda_py-signed-bundle-${CI_JOB_ID}
    - mkdir -p datadog_lambda_py-signed-bundle-${CI_JOB_ID}
    - cp .layers/datadog_lambda_py-*.zip datadog_lambda_py-signed-bundle-${CI_JOB_ID}

e2e-test:
  stage: e2e
  trigger:
    project: DataDog/serverless-e2e-tests
    strategy: depend
  rules:
    - if: '$SKIP_E2E_TESTS == "true"'
      when: never
    - when: on_success
  variables:
      LANGUAGES_SUBSET: python
      # These env vars are inherited from the dotenv reports of the publish-layer jobs
    {{- range (ds "runtimes").runtimes }}
    {{- if eq .arch "amd64" }}
    {{- $version := print (.name | strings.Trim "python") }}
      PYTHON_{{ $version }}_VERSION: $PYTHON_{{ $version }}_VERSION
    {{- end }}
    {{- end }}
  needs: {{ range (ds "runtimes").runtimes }}
    {{- if eq .arch "amd64" }}
      - "publish-layer-sandbox ({{ .name }}-{{ .arch }}): [{{ $e2e_region }}]"
    {{- end }}
    {{- end }}

e2e-test-status:
  stage: e2e
  image: registry.ddbuild.io/images/docker:20.10-py3
  tags: ["arch:amd64"]
  timeout: 3h
  rules:
    - if: '$SKIP_E2E_TESTS == "true"'
      when: never
    - when: on_success
  script: |
      GITLAB_API_TOKEN=$(aws ssm get-parameter --region us-east-1 --name "ci.${CI_PROJECT_NAME}.serverless-e2e-gitlab-token" --with-decryption --query "Parameter.Value" --out text)
      URL="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/pipelines/${CI_PIPELINE_ID}/bridges"
      echo "Fetching E2E job status from: $URL"
      while true; do
        RESPONSE=$(curl -s --header "PRIVATE-TOKEN: ${GITLAB_API_TOKEN}" "$URL")
        E2E_JOB_STATUS=$(echo "$RESPONSE" | jq -r '.[] | select(.name=="e2e-test") | .downstream_pipeline.status')
        echo -n "E2E job status: $E2E_JOB_STATUS, "
        if [ "$E2E_JOB_STATUS" == "success" ]; then
          echo "✅ E2E tests completed successfully"
          exit 0
        elif [ "$E2E_JOB_STATUS" == "failed" ]; then
          echo "❌ E2E tests failed"
          exit 1
        elif [ "$E2E_JOB_STATUS" == "running" ]; then
          echo "⏳ E2E tests are still running, retrying in 1 minute..."
        elif [ "$E2E_JOB_STATUS" == "canceled" ]; then
          echo "🚫 E2E tests were canceled"
          exit 1
        elif [ "$E2E_JOB_STATUS" == "skipped" ]; then
          echo "⏭️ E2E tests were skipped"
          exit 0
        else
          echo "❓ Unknown E2E test status: $E2E_JOB_STATUS, retrying in 1 minute..."
        fi
        sleep 60
      done
