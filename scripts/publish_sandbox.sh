#!/bin/bash
set -e

./scripts/build_layers.sh
aws-vault exec sandbox-account-admin -- ./scripts/sign_layers.sh sandbox
aws-vault exec sandbox-account-admin -- ./scripts/publish_layers.sh