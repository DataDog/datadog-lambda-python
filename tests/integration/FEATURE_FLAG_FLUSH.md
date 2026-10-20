# Feature flag invocation-end smoke test

Status: local wrapper/tracer integration is covered in `tests/test_feature_flags.py`.
The deployed ingestion test has not been run. Do not claim a supported published
layer until the release record below is populated.

## Existing examples and access

The smoke handler initializes its provider and client once at module scope and
reuses them across invocations.

This repository's `scripts/run_integration_tests.sh` documents
`sso-serverless-sandbox-account-admin`. `tests/integration/serverless.yml` uses
`eu-west-1`, a sandbox execution role, and a dedicated deployment bucket. Its
IAM restrictions require names beginning with `integration-tests`. Use that
approved sandbox or obtain an explicitly approved replacement account/role.
Verify that the selected profile can access the approved account before deploying.

## Assemble and deploy

1. Build a Python 3.11 layer containing both candidate changes: the tracer's
   internal flush contract version 1 and this Lambda library. The ordinary layer
   build installs the declared tracer dependency, so verify the zip actually
   contains the candidate tracer instead of a published version without the fix.
2. Package `feature_flags.py` and `openfeature-sdk`. Configure its handler as
   `feature_flags.handle`. It uses the ordinary Datadog wrapper and has no flush
   or shutdown calls. Reuse the approved sandbox's IAM and deployment settings
   from `serverless.yml`, with a unique `integration-tests-*` function name.
3. Configure `FFL_SMOKE_FLAG_KEY` with an existing string test flag that produces
   exposure events for the test subjects. Set `DD_SERVICE` to a unique smoke-test
   service, `DD_ENV` to the test environment and `DD_FEATURE_FLAG_FLUSH_TIMEOUT_MS=500`.
   Keep evaluation telemetry and exposure intake enabled.
4. For direct delivery, use `DD_FEATURE_FLAGS_CONFIGURATION_SOURCE=agentless`,
   the test organization's `DD_API_KEY`/`DD_SITE`, and no local Agent endpoint.
   Supply the API key through the sandbox's approved secret mechanism.
5. Validate Agent delivery separately with a reachable Agent that advertises the
   relevant EVP routes. The Lambda extension does not acquire new intake routes
   from this change; do not treat extension presence as proof of Agent EVP support.

## Validate

Invoke the same function three times with distinct synthetic subjects, for
example `{"subject":"ffl3412-<run>-1"}`, then a different subject with
`"raise":true`, then a third success. Distinct subjects avoid intentional exposure
deduplication. Confirm the second invocation returns the intentional handler
error, the other two succeed, and logs show the same `sandbox_id` with increasing
invocation counts. A changed sandbox ID means warm reuse was not demonstrated.

Check both evaluation and exposure ingestion for every subject at the configured
Datadog site, including the raising invocation. Capture the invocation request
IDs and ingestion evidence. `evaluation_ms` should be below the background flush
intervals; measure invocation duration separately because cleanup adds wait.
Endpoint acceptance can precede UI visibility. No further invocation or deliberate
sleep in the handler should be needed to trigger delivery.

Repeat with a slow/unavailable endpoint and a short remaining-time budget; verify
the original response/error is retained and the extra caller wait stays within
the configured cap or remaining time minus 100 ms. Inspect debug diagnostics for
incomplete flushes. Remove only the smoke-test stack/resources created by the run.

## Release record

Record the first supported **published** tracer version, Lambda library version,
and layer ARN/version together, plus runtime, architecture, configuration source,
service/environment, request IDs, and ingestion evidence. All are pending deployed
validation and release coordination. Release the tracer first, then the wrapper
and layer that contain it. Older tracer versions safely skip the capability.
