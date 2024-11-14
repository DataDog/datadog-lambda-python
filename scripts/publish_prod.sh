#!/bin/bash

# Use with `./publish_prod.sh <DESIRED_NEW_VERSION>

set -e

read -p "Are we only doing the simplified GovCloud release? ONLY IF THE NORMAL RELEASE IS DONE AND YOU HAVE DOWNLOADED THE LAYERS (y/n)? " GOVCLOUD_ONLY

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
if [ $GOVCLOUD_ONLY == "y" ]; then
    echo "Skipping PyPI check since this is a GovCloud-only release"

else
    read -p "Do you have access to PyPI (y/n)?" CONT
    if [ "$CONT" != "y" ]; then
        echo "Exiting"
        exit 1
    fi
fi

CURRENT_VERSION=$(poetry version --short)
LAYER_VERSION=$(echo $NEW_VERSION | cut -d '.' -f 2)

if [ $GOVCLOUD_ONLY == "y" ]; then
    echo "Skipping Libary Updates, code changes, layer builds and signing for GovCloud-only release"

else
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
        echo "Replacing version in pyproject.toml and datadog_lambda/version.py"
        echo

        poetry version ${NEW_VERSION}
        echo "__version__ = \"${NEW_VERSION}\"" > datadog_lambda/version.py
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
fi

read -p "Deploy layers to GovCloud AWS (y/n)?" CONT
if [ "$CONT" != "y" ]; then
    echo "Skipping deployment to GovCloud AWS"
else
    echo "Ensuring you have access to the AWS GovCloud account"
    aws-vault exec sso-govcloud-us1-fed-engineering -- aws sts get-caller-identity

    echo "Publishing layers to GovCloud AWS regions"
    VERSION=$LAYER_VERSION aws-vault exec sso-govcloud-us1-fed-engineering -- ./scripts/publish_layers.sh
fi

if [ $GOVCLOUD_ONLY == "y" ]; then
    echo "Skipping PyPI check and Github Release since this is a GovCloud-only release"

else
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
        git commit pyproject.toml datadog_lambda/version.py -m "Bump version to ${NEW_VERSION}"
        git push origin main
        git tag "v$LAYER_VERSION"
        git push origin "refs/tags/v$LAYER_VERSION"
    fi

    echo
    echo "Now create a new release with the tag v${LAYER_VERSION} created unless you have done this already"
    echo "https://github.com/DataDog/datadog-lambda-python/releases/new?tag=v$LAYER_VERSION&title=v$LAYER_VERSION"
fi
# Open a PR to the documentation repo to automatically bump layer version
VERSION=$LAYER_VERSION LAYER=datadog-lambda-python ./scripts/create_documentation_pr.sh
