#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
asset_name="codex-token-usage_0.1.38_linux_amd64.zip"
asset_sha256="9e40c0d5136ef88a43efd1dd48484e0d2ff6501f9ebfdc4930f1688ecb2c8d42"
asset_url="https://github.com/yujianwudi/codex-token-usage/releases/download/v0.1.38/${asset_name}"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

asset="${work}/${asset_name}"
if [[ $# -gt 1 ]]; then
  echo "Usage: $0 [cached-v0.1.38-linux-amd64-zip]" >&2
  exit 2
elif [[ $# -eq 1 ]]; then
  cp -- "$1" "${asset}"
else
  curl --fail --location --silent --show-error \
    --retry 3 --retry-all-errors \
    --connect-timeout 15 --max-time 120 \
    --output "${asset}" \
    "${asset_url}"
fi
printf '%s  %s\n' "${asset_sha256}" "${asset}" | sha256sum -c -

python3 - "${root}/schema.go" "${asset}" "${work}" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import sys
import zipfile

def snapshot(directory: pathlib.Path) -> dict[str, tuple[object, ...]]:
    result = {}
    for entry in sorted(directory.rglob("*"), key=lambda item: item.relative_to(directory).as_posix()):
        relative = entry.relative_to(directory).as_posix()
        if entry.is_symlink():
            result[relative] = ("symlink", os.readlink(entry))
        elif entry.is_file():
            raw = entry.read_bytes()
            result[relative] = ("file", len(raw), hashlib.sha256(raw).hexdigest())
        elif entry.is_dir():
            result[relative] = ("directory",)
        else:
            result[relative] = ("other", entry.stat().st_mode)
    return result


def create_v6_fixture(directory: pathlib.Path, schema: str) -> pathlib.Path:
    directory.mkdir(mode=0o700)
    (directory / "auth").mkdir(mode=0o700)
    database_path = directory / "usage.db"
    connection = sqlite3.connect(database_path)
    try:
        journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if str(journal_mode).lower() != "wal":
            raise SystemExit(f"failed to create WAL fixture: journal_mode={journal_mode!r}")
        connection.executescript(schema)
        connection.execute("PRAGMA user_version=6")
        connection.commit()
        quick_check = connection.execute("PRAGMA quick_check").fetchone()[0]
        if quick_check != "ok":
            raise SystemExit(f"fresh v6 fixture failed quick_check: {quick_check!r}")
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    finally:
        connection.close()
    database_path.chmod(0o600)
    return database_path


def logical_snapshot(database_path: pathlib.Path) -> dict[str, object]:
    connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
    try:
        schema_rows = connection.execute(
            "SELECT type,name,tbl_name,COALESCE(sql,'') FROM sqlite_schema ORDER BY type,name,tbl_name"
        ).fetchall()
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"
            ).fetchall()
        ]
        counts = {}
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            counts[table] = connection.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
        return {
            "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
            "quick_check": connection.execute("PRAGMA quick_check").fetchone()[0],
            "schema": schema_rows,
            "counts": counts,
            "store_state": connection.execute(
                "SELECT key,value FROM store_state ORDER BY key"
            ).fetchall(),
        }
    finally:
        connection.close()


def add_committed_wal_row(database_path: pathlib.Path) -> None:
    child = r'''
import os
import sqlite3
import sys

connection = sqlite3.connect(sys.argv[1])
connection.execute("PRAGMA wal_autocheckpoint=0")
connection.execute(
    "INSERT INTO store_state(key,value) VALUES('downgrade_guard_committed_wal','present')"
)
connection.commit()
os._exit(0)
'''
    subprocess.run([sys.executable, "-c", child, str(database_path)], check=True)
    wal_path = pathlib.Path(str(database_path) + "-wal")
    if not wal_path.is_file() or wal_path.stat().st_size == 0:
        raise SystemExit("failed to preserve the committed WAL downgrade fixture")


schema_path = pathlib.Path(sys.argv[1])
archive_path = pathlib.Path(sys.argv[2])
work = pathlib.Path(sys.argv[3])
library_path = work / "codex-token-usage.so"
with zipfile.ZipFile(archive_path) as archive:
    try:
        library_path.write_bytes(archive.read("codex-token-usage.so"))
    except KeyError as exc:
        raise SystemExit("v0.1.38 archive does not contain codex-token-usage.so") from exc
library_path.chmod(0o700)

source = schema_path.read_text(encoding="utf-8")
match = re.search(r"const schemaSQL = `\r?\n(.*?)\r?\n`", source, re.DOTALL)
if match is None:
    raise SystemExit("cannot extract schemaSQL from schema.go")

def invoke_v0138(data_dir: pathlib.Path) -> None:
    auth_dir = data_dir / "auth"
    auth_dir.mkdir(mode=0o700, exist_ok=True)
    isolated_home = work / f"home-{data_dir.name}"
    isolated_home.mkdir(mode=0o700)
    result_path = work / f"result-{data_dir.name}.json"
    child = r'''
import ctypes
import json
import os
import pathlib
import sys


class Buffer(ctypes.Structure):
    _fields_ = [("ptr", ctypes.c_void_p), ("len", ctypes.c_size_t)]


class PluginAPI(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("call", ctypes.c_void_p),
        ("free_buffer", ctypes.c_void_p),
        ("shutdown", ctypes.c_void_p),
    ]


library = ctypes.CDLL(sys.argv[1], mode=os.RTLD_LOCAL)
init = library.cliproxy_plugin_init
init.argtypes = (ctypes.c_void_p, ctypes.POINTER(PluginAPI))
init.restype = ctypes.c_int
call = library.cliproxyPluginCall
call.argtypes = (
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_uint8),
    ctypes.c_size_t,
    ctypes.POINTER(Buffer),
)
call.restype = ctypes.c_int
free_buffer = library.cliproxyPluginFree
free_buffer.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
free_buffer.restype = None
shutdown = library.cliproxyPluginShutdown
shutdown.argtypes = ()
shutdown.restype = None

plugin = PluginAPI()
init_code = init(None, ctypes.byref(plugin))
if init_code != 0 or plugin.abi_version != 1:
    raise SystemExit(f"v0.1.38 init failed: code={init_code} abi={plugin.abi_version}")
request = json.dumps(
    {
        "Provider": "codex",
        "RequestedAt": "2026-07-16T00:00:00Z",
        "Detail": {"TotalTokens": 1},
    },
    separators=(",", ":"),
).encode("utf-8")
request_buffer = (ctypes.c_uint8 * len(request)).from_buffer_copy(request)
response = Buffer()
try:
    code = call(b"usage.handle", request_buffer, len(request), ctypes.byref(response))
    raw_response = ctypes.string_at(response.ptr, response.len) if response.ptr else b""
finally:
    if response.ptr:
        free_buffer(response.ptr, response.len)
    shutdown()
pathlib.Path(sys.argv[2]).write_text(
    json.dumps({"code": code, "response": raw_response.decode("utf-8")}),
    encoding="utf-8",
)
'''
    child_env = os.environ.copy()
    child_env.update(
        {
            "HOME": str(isolated_home),
            "XDG_CONFIG_HOME": str(isolated_home / ".config"),
            "CPA_TOKEN_USAGE_DIR": str(data_dir),
            "CPA_AUTH_DIR": str(auth_dir),
            "CPA_CONFIG_PATH": str(data_dir / "missing-config.yaml"),
            "CPA_CONFIG_FILE": str(data_dir / "missing-config.yaml"),
        }
    )
    subprocess.run(
        [sys.executable, "-c", child, str(library_path), str(result_path)],
        check=True,
        env=child_env,
    )
    invocation = json.loads(result_path.read_text(encoding="utf-8"))
    result_path.unlink()
    if invocation.get("code") != 0:
        raise SystemExit(f"v0.1.38 usage.handle returned ABI code {invocation.get('code')}")
    try:
        envelope = json.loads(invocation.get("response", ""))
    except json.JSONDecodeError as exc:
        raise SystemExit("v0.1.38 returned invalid JSON") from exc
    result = envelope.get("result", {})
    expected_error = "usage database schema 6 is newer than supported schema 5"
    if envelope.get("ok") is not True or result.get("stored") is not False:
        raise SystemExit(f"v0.1.38 did not reject the v6 database: {envelope!r}")
    if expected_error not in str(result.get("error", "")):
        raise SystemExit(f"v0.1.38 did not return the explicit newer-schema error: {envelope!r}")


closed_dir = work / "closed-v6"
closed_database = create_v6_fixture(closed_dir, match.group(1))
closed_logical_before = logical_snapshot(closed_database)
closed_files_before = snapshot(closed_dir)
invoke_v0138(closed_dir)
if logical_snapshot(closed_database) != closed_logical_before:
    raise SystemExit("v0.1.38 changed the checkpointed v6 logical database")
closed_files_after = snapshot(closed_dir)
if closed_files_after != closed_files_before:
    raise SystemExit(
        "v0.1.38 changed the checkpointed v6 file set: "
        f"before={closed_files_before!r} after={closed_files_after!r}"
    )

wal_dir = work / "committed-wal-v6"
wal_database = create_v6_fixture(wal_dir, match.group(1))
wal_base_logical = logical_snapshot(wal_database)
add_committed_wal_row(wal_database)
wal_expected_logical = {
    "user_version": wal_base_logical["user_version"],
    "quick_check": wal_base_logical["quick_check"],
    "schema": list(wal_base_logical["schema"]),
    "counts": dict(wal_base_logical["counts"]),
    "store_state": sorted(
        list(wal_base_logical["store_state"])
        + [("downgrade_guard_committed_wal", "present")]
    ),
}
wal_expected_logical["counts"]["store_state"] += 1
wal_files_before = snapshot(wal_dir)
invoke_v0138(wal_dir)
wal_logical_after = logical_snapshot(wal_database)
if wal_logical_after != wal_expected_logical:
    raise SystemExit(
        "v0.1.38 changed v6 schema or rows while refusing a committed-WAL database: "
        f"expected={wal_expected_logical!r} after={wal_logical_after!r}"
    )
wal_files_after = snapshot(wal_dir)
sqlite_representation_files = {"usage.db", "usage.db-wal", "usage.db-shm"}
wal_non_database_before = {
    name: value for name, value in wal_files_before.items() if name not in sqlite_representation_files
}
wal_non_database_after = {
    name: value for name, value in wal_files_after.items() if name not in sqlite_representation_files
}
if wal_non_database_after != wal_non_database_before:
    raise SystemExit(
        "v0.1.38 created or changed non-database files while refusing v6: "
        f"before={wal_non_database_before!r} after={wal_non_database_after!r}"
    )

print("v0.1.38 downgrade guard passed: explicit refusal and logical schema/row preservation")
print(
    "committed-WAL representation changed="
    + str(wal_files_after != wal_files_before).lower()
    + "; old plugins remain forbidden from live v6 databases"
)
PY
