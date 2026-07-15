#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source scripts/semver.sh

mapfile -t source_versions < <(
  sed -n 's/^[[:space:]]*pluginVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' main.go |
    tr -d '\r'
)
# Backticks below are literal Markdown delimiters, not shell substitutions.
# shellcheck disable=SC2016
mapfile -t readme_versions < <(
  sed -n 's/^Current version: `\([^`]*\)`[[:space:]]*$/\1/p' README.md |
    tr -d '\r'
)
mapfile -t fixture_versions < <(
  sed -n 's/^version="\([^"]*\)"[[:space:]]*$/\1/p' scripts/test-verify-release-assets.sh |
    tr -d '\r'
)
mapfile -t readme_verification_versions < <(
  sed -n 's/^VERSION=\([^[:space:]]*\)[[:space:]]*$/\1/p' README.md |
    tr -d '\r'
)

if (( ${#source_versions[@]} != 1 )); then
  echo "Expected exactly one pluginVersion in main.go; found ${#source_versions[@]}" >&2
  exit 1
fi
if (( ${#readme_versions[@]} != 1 )); then
  echo "Expected exactly one current version in README.md; found ${#readme_versions[@]}" >&2
  exit 1
fi
if (( ${#fixture_versions[@]} != 1 )); then
  echo "Expected exactly one release test version; found ${#fixture_versions[@]}" >&2
  exit 1
fi
if (( ${#readme_verification_versions[@]} != 1 )); then
  echo "Expected exactly one verification command version in README.md; found ${#readme_verification_versions[@]}" >&2
  exit 1
fi

version="${source_versions[0]}"
if ! is_semver "${version}"; then
  echo "main.go pluginVersion is not SemVer: ${version}" >&2
  exit 1
fi
for candidate in \
  "${readme_versions[0]}" \
  "${fixture_versions[0]}" \
  "${readme_verification_versions[0]}"; do
  if [[ "${candidate}" != "${version}" ]]; then
    echo "Plugin version mismatch: source=${version} compared=${candidate}" >&2
    exit 1
  fi
done

platforms=(linux_amd64 linux_arm64 windows_amd64 darwin_amd64 darwin_arm64)
for platform in "${platforms[@]}"; do
  asset="codex-token-usage_${version}_${platform}.zip"
  if ! grep -Fq "${asset}" README.md; then
    echo "README.md is missing release asset: ${asset}" >&2
    exit 1
  fi
done

mapfile -t documented_asset_versions < <(
  sed -n 's/^codex-token-usage_\([^_]*\)_\(linux\|windows\|darwin\)_.*/\1/p' README.md
)
if (( ${#documented_asset_versions[@]} != ${#platforms[@]} )); then
  echo "Expected ${#platforms[@]} documented release archives; found ${#documented_asset_versions[@]}" >&2
  exit 1
fi
for candidate in "${documented_asset_versions[@]}"; do
  if [[ "${candidate}" != "${version}" ]]; then
    echo "README.md contains a stale release asset version: ${candidate}" >&2
    exit 1
  fi
done

if ! grep -Fq "## ${version} -" CHANGELOG.md; then
  echo "CHANGELOG.md has no entry for current version ${version}" >&2
  exit 1
fi

go_version="$(awk '$1 == "go" { print $2; exit }' go.mod | tr -d '\r')"
if [[ -z "${go_version}" ]]; then
  echo "Cannot determine Go version from go.mod" >&2
  exit 1
fi
mapfile -t workflow_go_versions < <(
  sed -n 's/^[[:space:]]*GO_VERSION:[[:space:]]*"\([^"]*\)".*/\1/p' \
    .github/workflows/ci.yml .github/workflows/release.yml |
    tr -d '\r'
)
if (( ${#workflow_go_versions[@]} != 2 )); then
  echo "Expected GO_VERSION in both workflows; found ${#workflow_go_versions[@]}" >&2
  exit 1
fi
for candidate in "${workflow_go_versions[@]}"; do
  if [[ "${candidate}" != "${go_version}" ]]; then
    echo "Go version mismatch: go.mod=${go_version} workflow=${candidate}" >&2
    exit 1
  fi
done
if ! grep -Fq "Release builds use Go \`${go_version}\`" README.md; then
  echo "README.md build Go version does not match go.mod ${go_version}" >&2
  exit 1
fi

mapfile -t govuln_versions < <(
  sed -n 's/^[[:space:]]*GOVULNCHECK_VERSION:[[:space:]]*"\([^"]*\)".*/\1/p' \
    .github/workflows/ci.yml .github/workflows/release.yml |
    tr -d '\r'
)
if (( ${#govuln_versions[@]} != 2 )) || [[ "${govuln_versions[0]}" != "${govuln_versions[1]}" ]]; then
  echo "GOVULNCHECK_VERSION must be present and equal in CI and release workflows" >&2
  exit 1
fi

echo "Version consistency checks passed: plugin=${version} go=${go_version} govulncheck=${govuln_versions[0]}"
