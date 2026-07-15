#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"
source scripts/semver.sh

plugin_id="codex-token-usage"
out_dir="${1:-dist}"
mkdir -p "${out_dir}"
out_dir="$(cd "${out_dir}" && pwd)"

source_version="$(sed -n 's/^[[:space:]]*pluginVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' main.go | head -n 1)"
version="${PLUGIN_VERSION:-${source_version}}"
if [[ -z "${source_version}" || -z "${version}" ]]; then
  echo "Cannot determine plugin version" >&2
  exit 1
fi
if [[ "${version}" != "${source_version}" ]]; then
  echo "PLUGIN_VERSION ${version} does not match source version ${source_version}" >&2
  exit 1
fi
if ! is_semver "${version}"; then
  echo "Invalid plugin version: ${version}" >&2
  exit 1
fi
export PLUGIN_VERSION="${version}"

for notice in LICENSE THIRD_PARTY_NOTICES.md; do
  if [[ ! -f "${notice}" ]]; then
    echo "Required release notice is missing: ${notice}" >&2
    exit 1
  fi
done

bash ./build.sh

goos="$(go env GOOS)"
goarch="$(go env GOARCH)"
ext="so"
case "${goos}" in
  windows) ext="dll" ;;
  darwin) ext="dylib" ;;
esac

artifact="${plugin_id}.${ext}"
zip_name="${plugin_id}_${version}_${goos}_${goarch}.zip"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

cp "${artifact}" LICENSE THIRD_PARTY_NOTICES.md "${tmp_dir}/"
release_files=("${artifact}" LICENSE THIRD_PARTY_NOTICES.md)

if command -v zip >/dev/null 2>&1; then
  (cd "${tmp_dir}" && zip -9 -q "${out_dir}/${zip_name}" "${release_files[@]}")
else
  python3 - "${tmp_dir}" "${out_dir}/${zip_name}" "${release_files[@]}" <<'PY'
import pathlib
import sys
import zipfile

tmp_dir = pathlib.Path(sys.argv[1])
zip_path = pathlib.Path(sys.argv[2])
files = sys.argv[3:]
zip_path.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for name in files:
        zf.write(tmp_dir / name, name)
PY
fi

checksum=""
if command -v sha256sum >/dev/null 2>&1; then
  checksum="$(cd "${out_dir}" && sha256sum "${zip_name}")"
else
  checksum="$(cd "${out_dir}" && shasum -a 256 "${zip_name}")"
fi

checksums="${out_dir}/checksums.txt"
tmp_checksums="$(mktemp)"
if [[ -f "${checksums}" ]]; then
  grep -Fv "  ${zip_name}" "${checksums}" > "${tmp_checksums}" || true
fi
printf '%s\n' "${checksum}" >> "${tmp_checksums}"
LC_ALL=C sort -k2,2 "${tmp_checksums}" > "${checksums}"
rm -f "${tmp_checksums}"

echo "Created ${out_dir}/${zip_name}"
echo "Updated ${checksums}"
