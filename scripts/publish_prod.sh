#!/bin/bash

# Use with `./publish_prod.sh <DESIRED_NEW_VERSION>

set -e

# Ensure on main, and pull the latest
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ $BRANCH != "main" ]; then
    echo "Not on main, aborting"
    exit 1
else
    echo "Updating main"
    git pull origin main
fi

# Ensure no uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo "Detected uncommitted changes, aborting"
    exit 1
fi

# Read the new version
if [ -z "$1" ]; then
    echo "Must specify a desired version number"
    exit 1
elif [[ ! $1 =~ [0-9]+\.[0-9]+\.[0-9]+ ]]; then
    echo "Must use a semantic version, e.g., 3.1.4"
    exit 1
else
    NEW_VERSION=$1
fi

# Ensure pypi registry access
read -p "Do you have access to PyPI (y/n)?" CONT
if [ "$CONT" != "y" ]; then
    echo "Exiting"
    exit 1
fi

CURRENT_VERSION=$(poetry version --short)
LAYER_VERSION=$(echo $NEW_VERSION | cut -d '.' -f 2)

read -p "Ready to update the library version from $CURRENT_VERSION to $NEW_VERSION and publish layer version $LAYER_VERSION (y/n)?" CONT
if [ "$CONT" != "y" ]; then
    echo "Exiting"
    exit 1
fi

echo "Answer 'n' if already done in a PR"
read -p "Update pyproject.toml version? (y/n)?" CONT
if [ "$CONT" != "y" ]; then
    echo "Skipping updating package.json version"
else
    echo
    echo "Replacing version in pyproject.toml"
    echo

    poetry version ${NEW_VERSION}
fi

echo
echo "Building layers..."
./scripts/build_layers.sh

echo
echo "Signing layers for commercial AWS regions"
aws-vault exec sso-prod-engineering -- ./scripts/sign_layers.sh prod

echo "Answer 'n' if GitLab already did this"
read -p "Deploy layers to commercial AWS (y/n)?" CONT
if [ "$CONT" != "y" ]; then
    echo "Skipping deployment to commercial AWS"
else
    echo "Ensuring you have access to the production AWS account"
    aws-vault exec sso-prod-engineering -- aws sts get-caller-identity

    echo
    echo "Publishing layers to commercial AWS regions"
    VERSION=$LAYER_VERSION aws-vault exec sso-prod-engineering --no-session -- ./scripts/publish_layers.sh
fi
read -p "Deploy layers to GovCloud AWS (y/n)?" CONT
if [ "$CONT" != "y" ]; then
    echo "Skipping deployment to GovCloud AWS"
else
    echo "Ensuring you have access to the AWS GovCloud account"
    ddsaml2aws login -a govcloud-us1-fed-human-engineering
    AWS_PROFILE=govcloud-us1-fed-human-engineering aws sts get-caller-identity

    echo "Publishing layers to GovCloud AWS regions"
    ddsaml2aws login -a govcloud-us1-fed-human-engineering
    VERSION=$LAYER_VERSION AWS_PROFILE=govcloud-us1-fed-human-engineering ./scripts/publish_layers.sh
fi

if [ "$CONT" != "y" ]; then
    echo "Exiting"
    exit 1
fi

echo "Answer 'n' if GitLab already did this"
read -p "Ready to publish $NEW_VERSION to PyPI (y/n)?" CONT
if [ "$CONT" != "y" ]; then
    echo "Skipping publishing to PyPI"
else
    echo
    echo "Publishing to https://pypi.org/project/datadog-lambda/"
    ./scripts/pypi.sh
fi


echo "Answer 'n' if you already released in GitHub"
read -p "Do you want to bump the version in GitHub? (y/n)" CONT
if [ "$CONT" != "y" ]; then
    echo "Skipping publishing updates to GitHub"
else
    echo
    echo 'Publishing updates to github'
    git commit pyproject.toml -m "Bump version to ${NEW_VERSION}"
    git push origin main
    git tag "v$LAYER_VERSION"
    git push origin "refs/tags/v$LAYER_VERSION"
fi

echo
echo "Now create a new release with the tag v${LAYER_VERSION} created unless you have done this already"
echo "https://github.com/DataDog/datadog-lambda-python/releases/new?tag=v$LAYER_VERSION&title=v$LAYER_VERSION"
# Open a PR to the documentation repo to automatically bump layer version
VERSION=$LAYER_VERSION LAYER=datadog-lambda-python ./scripts/create_documentation_pr.sh
