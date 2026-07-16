#!/usr/bin/env bash
set -euo pipefail

library="${1:-./codex-token-usage.so}"
target_os="${2:-$(go env GOOS)}"
target_arch="${3:-$(go env GOARCH)}"
if [[ ! -f "${library}" ]]; then
  echo "Shared library not found: ${library}" >&2
  exit 1
fi

if [[ "${target_os}" != "linux" ]]; then
  echo "Official ABI smoke tests support Linux only; got GOOS=${target_os}" >&2
  exit 2
fi
case "${target_arch}" in
  amd64 | arm64) ;;
  *)
    echo "Unsupported Linux ABI smoke-test architecture: ${target_arch}" >&2
    exit 2
    ;;
esac
ldd -r "${library}"

# The tagged panic-injection build is test-only. Check the exact library that
# will be packaged, on both supported Linux architectures, so a harness symbol or marker
# cannot slip into an uploaded asset after the separate Linux harness test.
for forbidden in CODEX_TOKEN_USAGE_ABI_PANIC ABI_PANIC_HARNESS_SECRET cliproxyTestSetPanicPoint cliproxyTestGetPanicPoint; do
  if strings "${library}" | grep -Fq "${forbidden}"; then
    echo "Release shared library contains panic harness marker: ${forbidden}" >&2
    exit 1
  fi
done

python_bin=""
for candidate in python3 python; do
  if command -v "${candidate}" >/dev/null 2>&1; then
    python_bin="${candidate}"
    break
  fi
done
if [[ -z "${python_bin}" ]]; then
  echo "Python is required for the shared-library load test" >&2
  exit 2
fi

"${python_bin}" - "${library}" <<'PY'
import ctypes
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1]).resolve()
if os.name == "nt":
    library = ctypes.CDLL(str(path))
else:
    library = ctypes.CDLL(str(path), mode=os.RTLD_LOCAL)
required = (
    "cliproxy_plugin_init",
    "cliproxyPluginCall",
    "cliproxyPluginFree",
    "cliproxyPluginShutdown",
)
for symbol in required:
    getattr(library, symbol)

init = library.cliproxy_plugin_init
init.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
init.restype = ctypes.c_int
result = init(None, None)
if result != 1:
    raise SystemExit(f"cliproxy_plugin_init(NULL, NULL) returned {result}, expected 1")

print(f"shared-library/ABI smoke passed: {path}")
PY
