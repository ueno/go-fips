#!/bin/bash

set -ex

TAG=${1}

if [ -z "${TAG}" ]; then
    echo "You must supply a tag for the Go submodule (for example go1.19.2)"
    exit 1
fi

git submodule add --force https://github.com/golang/go.git
git submodule foreach git checkout ${TAG}
