#!/bin/sh
# Fails when the avocado-ext-connect version in avocado.yaml differs from the
# [package] version in Cargo.toml. Run from the repository root.
set -eu

cargo=$(sed -n '/^\[package\]/,/^\[/s/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -n 1)
ext=$(sed -n "s/^    version: '\(.*\)'$/\1/p" avocado.yaml | head -n 1)

if [ -z "$ext" ]; then
    echo "::error::no literal version for avocado-ext-connect in avocado.yaml" >&2
    exit 1
fi
if [ "$ext" != "$cargo" ]; then
    echo "::error::avocado.yaml version '$ext' differs from Cargo.toml version '$cargo'" >&2
    exit 1
fi
echo "Extension version $ext matches Cargo.toml"
