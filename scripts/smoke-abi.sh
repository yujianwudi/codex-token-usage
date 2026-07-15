#!/usr/bin/env bash
set -euo pipefail

library="${1:-./codex-token-usage.so}"
target_os="${2:-$(go env GOOS)}"
target_arch="${3:-$(go env GOARCH)}"
if [[ ! -f "${library}" ]]; then
  echo "Shared library not found: ${library}" >&2
  exit 1
fi

required_symbols=(
  cliproxy_plugin_init
  cliproxyPluginCall
  cliproxyPluginFree
  cliproxyPluginShutdown
)

case "${target_os}" in
  linux)
    ldd -r "${library}"
    ;;
  darwin)
    exported="$(nm -gU "${library}")"
    for symbol in "${required_symbols[@]}"; do
      if ! grep -Eq "[[:space:]]_?${symbol}$" <<< "${exported}"; then
        echo "Missing Darwin ABI export: ${symbol}" >&2
        exit 1
      fi
    done
    otool -L "${library}"
    ;;
  windows)
    headers="$(objdump -f "${library}")"
    case "${target_arch}" in
      amd64)
        if ! grep -Eq 'file format (pei-x86-64|pe-x86-64)|architecture: i386:x86-64' <<< "${headers}"; then
          echo "Windows DLL is not amd64:" >&2
          echo "${headers}" >&2
          exit 1
        fi
        ;;
      *)
        echo "Unsupported Windows GOARCH for ABI smoke test: ${target_arch}" >&2
        exit 2
        ;;
    esac
    exported="$(objdump -p "${library}")"
    for symbol in "${required_symbols[@]}"; do
      if ! grep -Eq "[[:space:]]${symbol}$" <<< "${exported}"; then
        echo "Missing Windows ABI export: ${symbol}" >&2
        exit 1
      fi
    done
    ;;
  *)
    echo "Unsupported ABI smoke-test platform: ${target_os}" >&2
    exit 2
    ;;
esac

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
