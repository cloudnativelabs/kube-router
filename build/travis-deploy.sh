#!/usr/bin/env bash
set -o errexit
set -o pipefail

# Pull Request image tag format: PR00
if [ "${TRAVIS_EVENT_TYPE}" = "pull_request" ]; then
    PR_USER=$(echo "$TRAVIS_PULL_REQUEST_SLUG" | sed -e 's/\/.*//')
    if [ "$PR_USER" != "cloudnativelabs" ]; then
      echo "Not building/pushing PR $TRAVIS_PULL_REQUEST since only the cloudnativelabs user can access docker hub credentials"
      exit 0
    fi
    echo "Building/pushing PR$TRAVIS_PULL_REQUEST from $PR_USER"
    make push IMG_TAG="PR$TRAVIS_PULL_REQUEST" GOARCH=amd64
    make push IMG_TAG="PR$TRAVIS_PULL_REQUEST" GOARCH=arm64
    make push IMG_TAG="PR$TRAVIS_PULL_REQUEST" GOARCH=arm
    make push IMG_TAG="PR$TRAVIS_PULL_REQUEST" GOARCH=s390x
    exit 0
fi

# Release image tag format: v0.0.0 and latest
if [ -n "$TRAVIS_TAG" ]; then
    echo "Running Release build on Travis"
    make push-release RELEASE_TAG="amd64-$TRAVIS_TAG" GOARCH=amd64
    make push-release RELEASE_TAG="arm64-$TRAVIS_TAG" GOARCH=arm64
    make push-release RELEASE_TAG="arm-$TRAVIS_TAG" GOARCH=arm
    make push-release RELEASE_TAG="s390x-$TRAVIS_TAG" GOARCH=s390x

    echo "Pushing manifest on Travis"
    make push-manifest RELEASE_TAG="$TRAVIS_TAG"
    exit 0
fi

# Push image tag format: COMMIT
echo "Running push build on Travis"
make push
