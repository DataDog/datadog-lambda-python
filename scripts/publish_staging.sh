#!/bin/bash
set -e

./scripts/list_layers.sh
./scripts/build_layers.sh
./scripts/publish_layers.sh us-east-1