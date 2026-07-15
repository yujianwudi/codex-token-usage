#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in jq ln python3 sha256sum unzip zip; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "${tool} is required for release-asset verification tests" >&2
    exit 2
  fi
done

version="0.1.38"
tmp_root="$(mktemp -d)"
assets_dir="${tmp_root}/assets"
backups_dir="${tmp_root}/backups"
mkdir -p "${assets_dir}" "${backups_dir}"
trap 'rm -rf "${tmp_root}"' EXIT

make_fixture() {
  local platform="$1"
  local ext="$2"
  local binary_name="codex-token-usage.${ext}"
  local work_dir="${tmp_root}/work-${platform}"
  local archive="${assets_dir}/codex-token-usage_${version}_${platform}.zip"
  local sbom="${assets_dir}/codex-token-usage_${version}_${platform}.spdx.json"
  mkdir -p "${work_dir}"
  printf 'ZIP_PAYLOAD_%s' "${platform}" > "${work_dir}/${binary_name}"
  printf 'test license\n' > "${work_dir}/LICENSE"
  printf 'test notices\n' > "${work_dir}/THIRD_PARTY_NOTICES.md"
  (
    cd "${work_dir}"
    zip -0 -q "${archive}" "${binary_name}" LICENSE THIRD_PARTY_NOTICES.md
  )
  local binary_sha256
  binary_sha256="$(sha256sum "${work_dir}/${binary_name}" | awk '{print tolower($1)}')"
  jq -n \
    --arg binary "${binary_name}" \
    --arg platform "${platform}" \
    --arg sha256 "${binary_sha256}" \
    '{
      spdxVersion: "SPDX-2.3",
      dataLicense: "CC0-1.0",
      SPDXID: "SPDXRef-DOCUMENT",
      name: $binary,
      documentNamespace: ("https://example.invalid/spdx/" + $platform),
      creationInfo: {
        created: "2026-01-01T00:00:00Z",
        creators: ["Tool: verify-release-assets-test"]
      },
      packages: [{
        name: $binary,
        SPDXID: "SPDXRef-Package-root",
        checksums: [{
          algorithm: "SHA256",
          checksumValue: $sha256
        }]
      }],
      relationships: []
    }' > "${sbom}"
}

expect_rejected() {
  local description="$1"
  if bash scripts/verify-release-assets.sh "${version}" "${assets_dir}" >/dev/null 2>&1; then
    echo "release verification accepted ${description}" >&2
    exit 1
  fi
}

make_fixture linux_amd64 so
make_fixture linux_arm64 so
make_fixture darwin_amd64 dylib
make_fixture darwin_arm64 dylib
make_fixture windows_amd64 dll

bash scripts/verify-release-assets.sh "${version}" "${assets_dir}" >/dev/null
if [[ "$(wc -l < "${assets_dir}/checksums.txt" | tr -d ' ')" != "10" ]]; then
  echo "release verification did not generate exactly ten checksum entries" >&2
  exit 1
fi
if ! (cd "${assets_dir}" && sha256sum -c checksums.txt >/dev/null); then
  echo "generated release checksums did not verify" >&2
  exit 1
fi
shopt -s nullglob dotglob
final_entries=("${assets_dir}"/*)
shopt -u nullglob dotglob
if (( ${#final_entries[@]} != 11 )); then
  echo "verified release bundle has ${#final_entries[@]} entries, want 11" >&2
  exit 1
fi
for entry in "${final_entries[@]}"; do
  if [[ -L "${entry}" || ! -f "${entry}" ]]; then
    echo "verified release bundle retained a non-regular entry: ${entry}" >&2
    exit 1
  fi
done
rm -f "${assets_dir}/checksums.txt"

printf 'unexpected\n' > "${assets_dir}/unexpected.bin"
expect_rejected "an extra file extension"
rm -f "${assets_dir}/unexpected.bin"

mkdir "${assets_dir}/unexpected-directory"
expect_rejected "an extra directory"
rmdir "${assets_dir}/unexpected-directory"

archive="${assets_dir}/codex-token-usage_${version}_linux_amd64.zip"
archive_backup="${backups_dir}/linux_amd64.zip"
mv "${archive}" "${archive_backup}"
ln -s "${archive_backup}" "${archive}"
expect_rejected "a symlink in place of an expected archive"
rm -f "${archive}"
mv "${archive_backup}" "${archive}"

printf 'stale checksums\n' > "${assets_dir}/checksums.txt"
expect_rejected "a pre-existing checksums.txt"
rm -f "${assets_dir}/checksums.txt"

mv "${archive}" "${archive_backup}"
expect_rejected "a missing expected archive"
mv "${archive_backup}" "${archive}"

cp "${archive}" "${archive_backup}"
python3 - "${archive}" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
payload = path.read_bytes()
old = b"ZIP_PAYLOAD_linux_amd64"
new = b"XIP_PAYLOAD_linux_amd64"
if payload.count(old) != 1 or len(old) != len(new):
    raise SystemExit("cannot locate the stored ZIP payload sentinel")
path.write_bytes(payload.replace(old, new, 1))
PY
expect_rejected "an archive with a bad CRC"
mv "${archive_backup}" "${archive}"

sbom="${assets_dir}/codex-token-usage_${version}_linux_amd64.spdx.json"
sbom_backup="${backups_dir}/linux_amd64.spdx.json"
cp "${sbom}" "${sbom_backup}"
printf '{}\n' > "${sbom}"
expect_rejected "an incomplete SPDX document"
mv "${sbom_backup}" "${sbom}"

cp "${sbom}" "${sbom_backup}"
jq '(.packages[0].checksums[0].checksumValue) =
  "0000000000000000000000000000000000000000000000000000000000000000"' \
  "${sbom_backup}" > "${sbom}"
expect_rejected "an SPDX checksum mismatch"
mv "${sbom_backup}" "${sbom}"

bash scripts/verify-release-assets.sh "${version}" "${assets_dir}" >/dev/null
if [[ "$(wc -l < "${assets_dir}/checksums.txt" | tr -d ' ')" != "10" ]]; then
  echo "restored release bundle did not regenerate ten checksums" >&2
  exit 1
fi

echo "Release asset verification tests passed"
