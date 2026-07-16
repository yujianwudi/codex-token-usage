#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
source scripts/semver.sh

goos="$(go env GOOS)"
goarch="$(go env GOARCH)"
if [[ "${goos}" != "linux" ]]; then
  echo "Official codex-token-usage builds support Linux only; got GOOS=${goos}" >&2
  exit 2
fi
case "${goarch}" in
  amd64 | arm64) ;;
  *)
    echo "Unsupported Linux release architecture: ${goarch}" >&2
    exit 2
    ;;
esac
ext="so"

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
