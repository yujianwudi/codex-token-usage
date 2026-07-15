#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in jq python3 sha256sum unzip zip; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "${tool} is required for release-asset verification tests" >&2
    exit 2
  fi
done

version="0.1.34"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

make_fixture() {
  local platform="$1"
  local ext="$2"
  local binary_name="codex-token-usage.${ext}"
  local work_dir="${tmp_dir}/work-${platform}"
  local archive="${tmp_dir}/codex-token-usage_${version}_${platform}.zip"
  local sbom="${tmp_dir}/codex-token-usage_${version}_${platform}.spdx.json"
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

make_fixture linux_amd64 so
make_fixture linux_arm64 so
make_fixture darwin_amd64 dylib
make_fixture darwin_arm64 dylib
make_fixture windows_amd64 dll

bash scripts/verify-release-assets.sh "${version}" "${tmp_dir}" >/dev/null
if [[ "$(wc -l < "${tmp_dir}/checksums.txt" | tr -d ' ')" != "10" ]]; then
  echo "release verification did not checksum all ten release assets" >&2
  exit 1
fi

archive="${tmp_dir}/codex-token-usage_${version}_linux_amd64.zip"
cp "${archive}" "${archive}.bak"
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
if bash scripts/verify-release-assets.sh "${version}" "${tmp_dir}" >/dev/null 2>&1; then
  echo "release verification accepted an archive with a bad CRC" >&2
  exit 1
fi
mv "${archive}.bak" "${archive}"

sbom="${tmp_dir}/codex-token-usage_${version}_linux_amd64.spdx.json"
cp "${sbom}" "${sbom}.bak"
printf '{}\n' > "${sbom}"
if bash scripts/verify-release-assets.sh "${version}" "${tmp_dir}" >/dev/null 2>&1; then
  echo "release verification accepted an incomplete SPDX document" >&2
  exit 1
fi
mv "${sbom}.bak" "${sbom}"

cp "${sbom}" "${sbom}.bak"
jq '(.packages[0].checksums[0].checksumValue) =
  "0000000000000000000000000000000000000000000000000000000000000000"' \
  "${sbom}.bak" > "${sbom}"
if bash scripts/verify-release-assets.sh "${version}" "${tmp_dir}" >/dev/null 2>&1; then
  echo "release verification accepted an SPDX checksum mismatch" >&2
  exit 1
fi
mv "${sbom}.bak" "${sbom}"

echo "Release asset verification tests passed"
