#!/usr/bin/env bash
set -euo pipefail

library="${1:-./codex-token-usage.so}"
ceiling="${2:-2.31}"
if [[ ! -f "${library}" ]]; then
  echo "Shared library not found: ${library}" >&2
  exit 1
fi
if ! command -v readelf >/dev/null 2>&1; then
  echo "readelf is required to inspect glibc symbols" >&2
  exit 1
fi

required="$(
  readelf --version-info "${library}" \
    | { grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' || true; } \
    | sed 's/^GLIBC_//' \
    | sort -Vu \
    | tail -n 1
)"
if [[ -z "${required}" ]]; then
  echo "No versioned glibc dependency found in ${library}" >&2
  exit 1
fi

highest="$(printf '%s\n%s\n' "${required}" "${ceiling}" | sort -V | tail -n 1)"
if [[ "${highest}" != "${ceiling}" ]]; then
  echo "${library} requires glibc ${required}, above supported ceiling ${ceiling}" >&2
  exit 1
fi

echo "glibc compatibility check passed: requires ${required} (ceiling ${ceiling})"
