#!/bin/bash

# Use with `aws-vault exec PROFILE -- ./publish_prod.sh <DESIRED_NEW_VERSION>

set -e

BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo $BRANCH

if [ $BRANCH != "master" ]; then
    echo "Not on master, aborting"
    exit 1
fi

if [ -z "$AWS_ACCESS_KEY_ID" ]; then
    echo 'AWS_ACCESS_KEY_ID not set. Are you using aws-vault?'
    exit 1
fi

if [ -z "$AWS_SECRET_ACCESS_KEY" ]; then
    echo 'AWS_SECRET_ACCESS_KEY not set. Are you using aws-vault?'
    exit 1
fi

if [ -z "$AWS_SESSION_TOKEN" ]; then
    echo 'AWS_SESSION_TOKEN not set. Are you using aws-vault?'
    exit 1
fi

# Read the desired version
if [ -z "$1" ]; then
    echo "Must specify a desired version number"
    exit 1
elif [[ ! $1 =~ [0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "Must use a semantic version, e.g., 3.1.4"
    exit 1
else
    NEW_VERSION=$1
fi

echo 'Checking AWS Regions'
./scripts/list_layers.sh

read -p "Do the list look good?(y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

VERSION_LINE=$(sed -E -n 's/\"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\"/"\1.\2.\3"/p' ./datadog_lambda/__init__.py)
CURRENT_VERSION=$(echo "$VERSION_LINE" | cut -d '"' -f 2)
echo "$CURRENT_VERSION"

read -p "Ready to publish layers and update the version from $CURRENT_VERSION to $NEW_VERSION?(y/n)" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

echo ""
echo "Replacing __version__ in ./datadog_lambda/__init__.py"
echo ""
sed -i "" -E "s/\"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\"/\"$NEW_VERSION\"/" ./datadog_lambda/__init__.py

git commit ./datadog_lambda/__init__.py -m "Update module version to ${NEW_VERSION}"

echo ""
echo "Building layers..."
./scripts/build_layers.sh

echo ""
echo "Publishing layers to AWS regions..."
./scripts/publish_layers.sh

echo ""
echo 'Pushing updates to github'
git push origin master
git push origin "refs/tags/v$NEW_VERSION"

echo ""
echo "Publishing to https://pypi.org/project/datadog-lambda/"
./scripts/pypi.sh

echo ""
echo "Now create a new release with the tag v${NEW_VERSION} created"
echo "https://github.com/DataDog/datadog-lambda-python/releases/new"
echo ""
echo "Then publish a new serverless-plugin-datadog version with the new layer versions!"
echo ""

