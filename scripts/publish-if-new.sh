#!/usr/bin/env bash
# Publish a package iff its current version isn't already on the npm registry.
#
# Usage: bash scripts/publish-if-new.sh <package-dir>
#
# Reads <package-dir>/package.json for `name` + `version`, queries the registry
# for that exact "name@version", and runs `npm publish --access public` only
# if the version isn't published yet. Auth/network errors still fail the
# script. Re-running the same release tag is a no-op for already-published
# packages.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <package-dir>" >&2
  exit 2
fi

pkg_dir="$1"
if [[ ! -f "$pkg_dir/package.json" ]]; then
  echo "error: $pkg_dir/package.json not found" >&2
  exit 2
fi

name=$(node -p "require('./$pkg_dir/package.json').name")
version=$(node -p "require('./$pkg_dir/package.json').version")

if [[ -z "$name" || -z "$version" ]]; then
  echo "error: missing name/version in $pkg_dir/package.json" >&2
  exit 2
fi

echo "Checking if $name@$version is already on the registry..."

# `npm view <name>@<version> version` exits 0 with empty output if the
# version doesn't exist (and no other versions match). Non-empty stdout
# means the exact version is already published.
existing=$(npm view "${name}@${version}" version 2>/dev/null || true)

if [[ -n "$existing" ]]; then
  echo "  -> $name@$version already published, skipping."
  exit 0
fi

echo "  -> $name@$version not yet published, publishing now."
cd "$pkg_dir" && npm publish --access public
