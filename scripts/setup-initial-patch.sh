#!/bin/bash

set -ex

ROOT=$(pwd)

# Function to clean things up if any portion of the script fails.
function cleanup() {
    # shellcheck disable=SC2181
    if [ "0" != "${?}" ]; then
        cd "${ROOT}"
        rm -rf go
    fi
}
trap cleanup EXIT

function usage() {
  echo "Sets up new Go version for FIPS support. If you provide the flag -r you can specify a replacement for the openssl-fips backend."
}

replacement=""

while getopts "r:" o; do
    case "${o}" in
        r)
            replacement=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

TAG=${1}

# Copy commits from wip/goX.Y.Z-openssl branch and store them in patches/.
git format-patch -o patches "${TAG}..wip/${TAG}-openssl"

"${ROOT}"/scripts/setup-go-submodule.sh "${TAG}"

# Enter the submodule directory.
cd go
ORIGINAL_GIT_SHA=$(git rev-parse HEAD)

# Apply the existing patches
git am "${ROOT}"/patches/0*.patch

"${ROOT}"/scripts/create-vendor-patch.sh "${replacement}"

# Clean things up again after we've generated the patch.
git reset --hard "${ORIGINAL_GIT_SHA}"
