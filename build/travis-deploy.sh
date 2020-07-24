#!/usr/bin/env bash
set -o errexit
set -o pipefail

GOARCHES=(amd64 arm64 arm s390x ppc64le)

# Pull Request image tag format: PR00
if [ "${TRAVIS_EVENT_TYPE}" = "pull_request" ]; then
    PR_USER=$(echo "${TRAVIS_PULL_REQUEST_SLUG}" | sed -e 's/\/.*//')
    if [ "${PR_USER}" != "cloudnativelabs" ]; then
      echo "Not building/pushing PR ${TRAVIS_PULL_REQUEST} since only the cloudnativelabs user can access docker hub credentials"
      exit 0
    fi
    echo "Building/pushing PR${TRAVIS_PULL_REQUEST} from ${PR_USER}"
    for GOARCH in "${GOARCHES[@]}"; do
      make push IMG_TAG="${GOARCH}-PR${TRAVIS_PULL_REQUEST}" GOARCH="${GOARCH}"
      make clean IMG_TAG="${GOARCH}-PR${TRAVIS_PULL_REQUEST}" GOARCH="${GOARCH}"
    done
    echo "Pushing PR manifest on Travis"
    make push-manifest MANIFEST_TAG="PR${TRAVIS_PULL_REQUEST}"
    exit 0
fi

# Release image tag format: v0.0.0 and latest
if [ -n "${TRAVIS_TAG}" ]; then
    echo "Running Release build on Travis"
    for GOARCH in "${GOARCHES[@]}"; do
      make push-release RELEASE_TAG="${GOARCH}-${TRAVIS_TAG}" GOARCH="${GOARCH}"
      make clean RELEASE_TAG="${GOARCH}-${TRAVIS_TAG}" GOARCH="${GOARCH}"
    done
    echo "Pushing release manifest on Travis"
    make push-manifest-release RELEASE_TAG="${TRAVIS_TAG}"
    exit 0
fi

# Push image tag format: COMMIT
echo "Running push build on Travis"
for GOARCH in "${GOARCHES[@]}"; do
  make push GOARCH="${GOARCH}"
  make clean GOARCH="${GOARCH}"
done
echo "Pushing manifest on Travis"
make push-manifest

