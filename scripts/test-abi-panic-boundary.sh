#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Native ABI panic boundary harness currently requires Linux" >&2
  exit 2
fi
for tool in cc go nm strings; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "${tool} is required for the ABI panic boundary harness" >&2
    exit 2
  fi
done

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/codex-token-usage-abi-panic.XXXXXX")"
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

release_library="${work_dir}/codex-token-usage-release.so"
harness_library="${work_dir}/codex-token-usage-harness.so"
harness_binary="${work_dir}/abi-panic-harness"

CGO_ENABLED=1 go build -trimpath -buildmode=c-shared -o "${release_library}" .
for symbol in cliproxyTestSetPanicPoint cliproxyTestGetPanicPoint; do
  if nm -D --defined-only "${release_library}" | grep -Fq "${symbol}"; then
    echo "Production shared library exposes ABI panic injection symbol ${symbol}" >&2
    exit 1
  fi
done
for forbidden in CODEX_TOKEN_USAGE_ABI_PANIC ABI_PANIC_HARNESS_SECRET cliproxyTestSetPanicPoint cliproxyTestGetPanicPoint; do
  if strings "${release_library}" | grep -Fq "${forbidden}"; then
    echo "Production shared library contains panic harness marker: ${forbidden}" >&2
    exit 1
  fi
done

CGO_ENABLED=1 go build -trimpath -tags abi_panic_harness -buildmode=c-shared -o "${harness_library}" .
if ! nm -D --defined-only "${harness_library}" | grep -Eq '[[:space:]]cliproxyTestSetPanicPoint$'; then
  echo "Tagged shared library is missing the ABI panic injection symbol" >&2
  exit 1
fi
if ! nm -D --defined-only "${harness_library}" | grep -Eq '[[:space:]]cliproxyTestGetPanicPoint$'; then
  echo "Tagged shared library is missing the ABI panic state symbol" >&2
  exit 1
fi

cc -std=c11 -O2 -Wall -Wextra -Werror \
  scripts/native/abi_panic_harness.c \
  -ldl \
  -o "${harness_binary}"

mkdir -p "${work_dir}/plugin-data" "${work_dir}/auth"
CPA_TOKEN_USAGE_DIR="${work_dir}/plugin-data" \
CPA_AUTH_DIR="${work_dir}/auth" \
  "${harness_binary}" "${harness_library}"

go test -count=1 -tags abi_panic_harness -run '^TestABI' ./...

echo "ABI panic boundary tests passed"
