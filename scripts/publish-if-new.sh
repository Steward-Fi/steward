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

view_log="$(mktemp)"
set +e
existing=$(npm view "${name}@${version}" version 2>"$view_log")
view_status=$?
set -e

if [[ $view_status -eq 0 && -n "$existing" ]]; then
  echo "  -> $name@$version already published, skipping."
  rm -f "$view_log"
  exit 0
fi

if [[ $view_status -ne 0 ]] && ! grep -q "No match found for version ${version}" "$view_log"; then
  cat "$view_log" >&2
  echo "error: failed to query npm registry for $name@$version." >&2
  echo "       Auth, permission, registry, and network errors are not treated as publishable." >&2
  rm -f "$view_log"
  exit "$view_status"
fi
rm -f "$view_log"

echo "  -> $name@$version not yet published, publishing now."

if [[ "$name" == @*/* ]]; then
  scope="${name%%/*}"
  if ! npm whoami >/dev/null 2>&1; then
    echo "error: npm authentication failed before publishing $name." >&2
    echo "       Ensure NODE_AUTH_TOKEN/NPM_TOKEN is a valid npm automation token with publish access to ${scope}." >&2
    exit 1
  fi
fi

publish_log="$(mktemp)"
set +e
(cd "$pkg_dir" && npm publish --access public) 2>&1 | tee "$publish_log"
publish_status=${PIPESTATUS[0]}
set -e

if [[ $publish_status -eq 0 ]]; then
  rm -f "$publish_log"
  exit 0
fi

if grep -q "Not Found - PUT .*${name//@/%40}" "$publish_log" || grep -q "npm error 404 Not Found - PUT" "$publish_log"; then
  echo "error: npm rejected publishing $name with 404." >&2
  echo "       For scoped packages this usually means the npm token lacks publish access to the scope," >&2
  echo "       the scope does not exist for that npm account, or package creation is not permitted." >&2
  echo "       Update the NPM_TOKEN secret to an npm automation token that can publish ${name}." >&2
fi
rm -f "$publish_log"
exit "$publish_status"
