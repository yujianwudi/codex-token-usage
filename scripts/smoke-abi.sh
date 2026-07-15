#!/usr/bin/env bash
set -euo pipefail

library="${1:-./codex-token-usage.so}"
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "The dlopen smoke test currently supports Linux only" >&2
  exit 2
fi
if [[ ! -f "${library}" ]]; then
  echo "Shared library not found: ${library}" >&2
  exit 1
fi

ldd -r "${library}"
python3 - "${library}" <<'PY'
import ctypes
import os
import pathlib
import sys

path = pathlib.Path(sys.argv[1]).resolve()
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

print(f"dlopen/ABI smoke passed: {path}")
PY
