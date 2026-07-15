#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
mock_bin="${tmp_dir}/bin"
mkdir -p "${mock_bin}"
touch "${tmp_dir}/plugin.dylib"

make_mock() {
  local name="$1"
  shift
  printf '#!/usr/bin/env bash\n%s\n' "$*" > "${mock_bin}/${name}"
  chmod +x "${mock_bin}/${name}"
}

make_mock uname 'echo Darwin'
make_mock file 'echo "Mach-O 64-bit dynamically linked shared library x86_64"'
make_mock lipo 'echo "${MOCK_MACHO_ARCH:-x86_64}"'
make_mock otool 'printf "      cmd LC_BUILD_VERSION\\n    minos %s\\n" "${MOCK_MACOS_MIN:-12.0}"'

PATH="${mock_bin}:${PATH}" MOCK_MACHO_ARCH=x86_64 MOCK_MACOS_MIN=12.0 \
  bash scripts/check-macho.sh "${tmp_dir}/plugin.dylib" amd64 12.0 >/dev/null

if PATH="${mock_bin}:${PATH}" MOCK_MACHO_ARCH=arm64 MOCK_MACOS_MIN=12.0 \
  bash scripts/check-macho.sh "${tmp_dir}/plugin.dylib" amd64 12.0 >/dev/null 2>&1; then
  echo "Mach-O gate accepted the wrong architecture" >&2
  exit 1
fi

if PATH="${mock_bin}:${PATH}" MOCK_MACHO_ARCH=x86_64 MOCK_MACOS_MIN=15.0 \
  bash scripts/check-macho.sh "${tmp_dir}/plugin.dylib" amd64 12.0 >/dev/null 2>&1; then
  echo "Mach-O gate accepted a minimum macOS above the target" >&2
  exit 1
fi

if PATH="${mock_bin}:${PATH}" MOCK_MACHO_ARCH=x86_64 MOCK_MACOS_MIN=11.0 \
  bash scripts/check-macho.sh "${tmp_dir}/plugin.dylib" amd64 12.0 >/dev/null 2>&1; then
  echo "Mach-O gate accepted a minimum macOS below the supported target" >&2
  exit 1
fi

echo "Mach-O gate tests passed"
