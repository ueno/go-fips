#!/bin/bash

set -ex

# Add new openssl backend to module and vendor it.
cd src
go get github.com/golang-fips/openssl-fips

replace="${1}"
if [ -n "${replace}" ]; then
    echo "replace github.com/golang-fips/openssl-fips => ${replace}" >> go.mod
fi
go mod tidy -go=1.16
go mod vendor

# Generate the final patch.
git add .
git commit -m "Vendor in openssl-fips module"
git format-patch --start-number 1000 -1 -o ../../patches
