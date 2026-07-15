#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in go grep python3 sed sort; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "${tool} is required for third-party notice verification" >&2
    exit 2
  fi
done

go mod download

for required_file in LICENSE THIRD_PARTY_NOTICES.md; do
  if [[ ! -s "${required_file}" ]]; then
    echo "Required license file is missing or empty: ${required_file}" >&2
    exit 1
  fi
done

grep -Fq "MIT License" LICENSE || {
  echo "Project LICENSE is not the expected MIT license" >&2
  exit 1
}
grep -Fq "Copyright (c) 2026 Codex Token Usage Contributors" LICENSE || {
  echo "Project LICENSE copyright marker is missing" >&2
  exit 1
}

for marker in \
  "Go runtime, standard library, and golang.org/x/sys" \
  "License: BSD-3-Clause" \
  "github.com/mattn/go-sqlite3" \
  "The bundled SQLite amalgamation is in the public domain" \
  "GPTSession2CPAandSub2API-derived credential mapping"; do
  if ! grep -Fq "${marker}" THIRD_PARTY_NOTICES.md; then
    echo "Third-party notice marker is missing: ${marker}" >&2
    exit 1
  fi
done

mapfile -t modules < <(
  go list -m -f '{{if not .Main}}{{.Path}}{{end}}' all |
    sed '/^$/d' |
    LC_ALL=C sort -u
)

if (( ${#modules[@]} == 0 )); then
  echo "No third-party Go modules were found" >&2
  exit 1
fi

license_files=("$(go env GOROOT)/LICENSE")
for module in "${modules[@]}"; do
  if ! grep -Fq "${module}" THIRD_PARTY_NOTICES.md; then
    echo "Third-party module is missing from notices: ${module}" >&2
    exit 1
  fi

  case "${module}" in
    github.com/mattn/go-sqlite3 | golang.org/x/sys) ;;
    *)
      echo "Unreviewed Go module license: ${module}" >&2
      echo "Add its exact license and attribution to THIRD_PARTY_NOTICES.md, then update this gate" >&2
      exit 1
      ;;
  esac

  module_dir="$(go list -m -f '{{.Dir}}' "${module}")"
  module_license="${module_dir}/LICENSE"
  if [[ ! -s "${module_license}" ]]; then
    echo "Cannot locate LICENSE for ${module}: ${module_license}" >&2
    exit 1
  fi
  license_files+=("${module_license}")
done

python3 - THIRD_PARTY_NOTICES.md "${license_files[@]}" <<'PY'
import pathlib
import sys

notice_path = pathlib.Path(sys.argv[1])
notice = notice_path.read_text(encoding="utf-8").replace("\r\n", "\n")
for license_name in sys.argv[2:]:
    license_path = pathlib.Path(license_name)
    license_text = license_path.read_text(encoding="utf-8").replace("\r\n", "\n").strip()
    if not license_text or license_text not in notice:
        raise SystemExit(
            f"{notice_path} does not contain the exact license text from {license_path}"
        )
PY

echo "Third-party license notices cover the Go toolchain and all modules"
