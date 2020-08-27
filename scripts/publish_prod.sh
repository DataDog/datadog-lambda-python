#!/bin/bash
set -e

BRANCH=$(git rev-parse --abbrev-ref HEAD)
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

echo 'Checking Regions'
# ./scripts/list_layers.sh
echo "layer 1"

# read -p "Do the list look good? " -n 1 -r
# echo
# if [[ ! $REPLY =~ ^[Yy]$ ]]
# then
#     [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
# fi
SEMVER_REGEX="(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(\\-[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?$"
VERSION_LINE=$(sed -E -n 's/\"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\"/"\1.\2.\3"/p' ./scripts/file.txt)

echo "$VERSION_LINE"
MINOR_VERSION_NUM=$(echo "$VERSION_LINE" | cut -d '.' -f 2)

echo "$MINOR_VERSION_NUM"

NEW_VERSION=$(($MINOR_VERSION_NUM + 1))
echo $NEW_VERSION

read -p "Does this Minor version LGTY? ${MINOR_VERSION_NUM}" -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi

echo "Replacing __version__ in ./datadog_lambda/__init__.py"
sed -i "" -E "s/\"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\"/\"\1.${NEW_VERSION}.\3\"/" ./scripts/file.txt



# PY_FILE=$(cat "./datadog_lambda/__init__.py")

# echo $PY_FILE
# echo "WTF"

# NEW_VERSION=$(echo $PY_FILE | grep -o "$SEMVER_REGEX" )
# NEW_VERSION=$(echo $PY_FILE | grep -o "[0-9]+.([0-9]+).[0-9]+")

# echo $NEW_VERSION

# echo 'Publishing to Node'
# yarn build
# yarn publish --new-version "$PACKAGE_VERSION"

# echo 'Tagging Release'
# git tag "v$PACKAGE_VERSION"
# git push origin "refs/tags/v$PACKAGE_VERSION"

# echo 'Publishing Lambda Layer'
# ./scripts/build_layers.sh
# ./scripts/publish_layers.sh