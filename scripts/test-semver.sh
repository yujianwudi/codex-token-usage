#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source scripts/semver.sh

valid=(0.1.34 1.2.3-rc.1 1.2.3-alpha.beta 1.2.3+build.7 1.2.3-rc.1+build.7)
invalid=(01.2.3 1.02.3 1.2.03 1.2.3-01 1.2.3-alpha.01 1.2 1.2.3- 1.2.3+)

for version in "${valid[@]}"; do
  is_semver "${version}" || { echo "valid SemVer rejected: ${version}" >&2; exit 1; }
done
for version in "${invalid[@]}"; do
  if is_semver "${version}"; then
    echo "invalid SemVer accepted: ${version}" >&2
    exit 1
  fi
done

echo "SemVer validation passed"
