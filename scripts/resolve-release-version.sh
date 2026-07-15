#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source scripts/semver.sh

tag="${1:-${GITHUB_REF_NAME:-}}"
tag_version="${tag#v}"
if [[ "${tag}" != v* ]] || ! is_semver "${tag_version}"; then
  echo "Release ref must be a semantic version tag such as v0.1.33; got: ${tag:-<empty>}" >&2
  exit 1
fi

source_version="$(sed -n 's/^[[:space:]]*pluginVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' main.go | head -n 1)"
if [[ -z "${source_version}" ]]; then
  echo "Cannot determine pluginVersion from main.go" >&2
  exit 1
fi
if [[ "${tag_version}" != "${source_version}" ]]; then
  echo "Tag version ${tag_version} does not match main.go pluginVersion ${source_version}" >&2
  exit 1
fi

printf '%s\n' "${tag_version}"
