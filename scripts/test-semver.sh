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

stable=(0.1.39 100000000000000000000000.2.3)
for version in "${stable[@]}"; do
  is_stable_semver "${version}" || { echo "stable SemVer rejected: ${version}" >&2; exit 1; }
done
for version in 1.2.3-rc.1 1.2.3+build.7; do
  if is_stable_semver "${version}"; then
    echo "non-stable SemVer accepted as stable: ${version}" >&2
    exit 1
  fi
done

for comparison in \
  "0.1.39 0.1.38" \
  "1.0.0 0.999.999" \
  "100000000000000000000000.0.0 99999999999999999999999.999.999"; do
  read -r candidate baseline <<< "${comparison}"
  semver_stable_gt "${candidate}" "${baseline}" || { echo "newer stable SemVer rejected: ${candidate} > ${baseline}" >&2; exit 1; }
done
for comparison in "0.1.38 0.1.39" "0.1.39 0.1.39" "1.2.3-rc.1 1.2.2"; do
  read -r candidate baseline <<< "${comparison}"
  if semver_stable_gt "${candidate}" "${baseline}"; then
    echo "non-newer stable SemVer accepted: ${candidate} > ${baseline}" >&2
    exit 1
  fi
done

echo "SemVer validation passed"
