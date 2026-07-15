#!/usr/bin/env bash
set -euo pipefail

binary="${1:?usage: check-macho.sh BINARY GOARCH EXPECTED_MACOS_VERSION}"
goarch="${2:?usage: check-macho.sh BINARY GOARCH EXPECTED_MACOS_VERSION}"
expected_macos="${3:?usage: check-macho.sh BINARY GOARCH EXPECTED_MACOS_VERSION}"

if [[ ! -f "${binary}" ]]; then
  echo "Mach-O binary not found: ${binary}" >&2
  exit 1
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Mach-O validation requires macOS" >&2
  exit 2
fi

case "${goarch}" in
  amd64) expected_arch="x86_64" ;;
  arm64) expected_arch="arm64" ;;
  *)
    echo "Unsupported Darwin GOARCH: ${goarch}" >&2
    exit 2
    ;;
esac

file_description="$(file -b "${binary}")"
if [[ "${file_description}" != *Mach-O* || "${file_description}" != *"dynamically linked shared library"* ]]; then
  echo "Expected a Mach-O shared library, got: ${file_description}" >&2
  exit 1
fi

actual_arches="$(lipo -archs "${binary}" | xargs)"
if [[ "${actual_arches}" != "${expected_arch}" ]]; then
  echo "Mach-O architecture mismatch: expected ${expected_arch}, got ${actual_arches}" >&2
  exit 1
fi

min_macos="$(otool -l "${binary}" | awk '
  $1 == "cmd" { command = $2; next }
  command == "LC_BUILD_VERSION" && $1 == "minos" { print $2; exit }
  command == "LC_VERSION_MIN_MACOSX" && $1 == "version" { print $2; exit }
')"
if [[ -z "${min_macos}" ]]; then
  echo "Mach-O binary has no macOS minimum-version load command" >&2
  exit 1
fi

version_lte() {
  awk -v left="$1" -v right="$2" 'BEGIN {
    left_count = split(left, left_parts, ".")
    right_count = split(right, right_parts, ".")
    count = left_count > right_count ? left_count : right_count
    for (part = 1; part <= count; part++) {
      left_value = part <= left_count ? left_parts[part] + 0 : 0
      right_value = part <= right_count ? right_parts[part] + 0 : 0
      if (left_value < right_value) exit 0
      if (left_value > right_value) exit 1
    }
    exit 0
  }'
}

if ! version_lte "${min_macos}" "${expected_macos}" || ! version_lte "${expected_macos}" "${min_macos}"; then
  echo "Mach-O minimum macOS mismatch: expected ${expected_macos}, got ${min_macos}" >&2
  exit 1
fi

echo "Mach-O gate passed: arch=${actual_arches} min_macos=${min_macos}"
