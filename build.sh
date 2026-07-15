#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
source scripts/semver.sh

goos="$(go env GOOS)"
ext="so"
case "${goos}" in
  windows) ext="dll" ;;
  darwin)
    ext="dylib"
    # Go 1.26 supports macOS 12 and later. Pin the deployment target so a
    # newer hosted runner cannot silently raise the plugin's minimum macOS.
    export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-12.0}"
    if [[ ! "${MACOSX_DEPLOYMENT_TARGET}" =~ ^[0-9]+(\.[0-9]+){1,2}$ ]]; then
      echo "Invalid MACOSX_DEPLOYMENT_TARGET: ${MACOSX_DEPLOYMENT_TARGET}" >&2
      exit 1
    fi
    ;;
esac

ldflags="-s -w"
if [[ -n "${PLUGIN_VERSION:-}" ]]; then
  if ! is_semver "${PLUGIN_VERSION}"; then
    echo "Invalid PLUGIN_VERSION: ${PLUGIN_VERSION}" >&2
    exit 1
  fi
  ldflags="${ldflags} -X 'main.pluginVersion=${PLUGIN_VERSION}'"
fi
if [[ -n "${PLUGIN_AUTHOR:-}" ]]; then
  ldflags="${ldflags} -X 'main.pluginAuthor=${PLUGIN_AUTHOR}'"
fi
if [[ -n "${PLUGIN_REPOSITORY:-}" ]]; then
  ldflags="${ldflags} -X 'main.pluginRepository=${PLUGIN_REPOSITORY}'"
fi

artifact="codex-token-usage.${ext}"
CGO_ENABLED="${CGO_ENABLED:-1}" go build \
  -buildvcs=false \
  -trimpath \
  -ldflags="${ldflags}" \
  -buildmode=c-shared \
  -o "${artifact}" \
  .

if [[ "${SKIP_STRIP:-0}" != "1" ]] && command -v strip >/dev/null 2>&1; then
  strip "${artifact}" 2>/dev/null || true
fi

echo "Built $(pwd)/${artifact}"
