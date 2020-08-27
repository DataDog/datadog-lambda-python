#!/bin/bash
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

echo 'Checking AWS Regions'
./scripts/list_layers.sh

read -p "Do the list look good?(y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

VERSION_LINE=$(sed -E -n 's/\"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\"/"\1.\2.\3"/p' ./datadog_lambda/__init__.py)
MINOR_VERSION_NUM=$(echo "$VERSION_LINE" | cut -d '.' -f 2)
echo ""
echo "Current version found: $MINOR_VERSION_NUM"
echo ""
NEW_VERSION=$(($MINOR_VERSION_NUM + 1))

read -p "Ready to publish layers and update the minor version. $MINOR_VERSION_NUM to $NEW_VERSION?(y/n)" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

echo ""
echo "Replacing __version__ in ./datadog_lambda/__init__.py"
echo ""
sed -i "" -E "s/\"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\"/\"\1.${NEW_VERSION}.\3\"/" ./datadog_lambda/__init__.py

git commit ./datadog_lambda/__init__.py -m "Update module minor version to ${NEW_VERSION}"

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
echo "https://github.com/DataDog/devops/wiki/Datadog-Serverless-Plugin#release"
echo ""

