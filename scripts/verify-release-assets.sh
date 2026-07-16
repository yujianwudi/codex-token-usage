#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: verify-release-assets.sh VERSION DIRECTORY}"
directory="${2:?usage: verify-release-assets.sh VERSION DIRECTORY}"
if [[ ! -d "${directory}" ]]; then
  echo "Release asset directory not found: ${directory}" >&2
  exit 1
fi
for tool in awk diff jq mktemp sha256sum sort tr unzip wc; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "${tool} is required to verify release assets" >&2
    exit 2
  fi
done

platforms=(
  linux_amd64
  linux_arm64
)
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

release_assets=()
for platform in "${platforms[@]}"; do
  archive_name="codex-token-usage_${version}_${platform}.zip"
  sbom_name="codex-token-usage_${version}_${platform}.spdx.json"
  release_assets+=("${archive_name}" "${sbom_name}")
done

# The verified input bundle is closed: exactly two Linux archives and two SPDX
# documents, all as top-level regular files. In particular, reject stale
# checksums, hidden files, directories, and symlinks before inspecting content.
shopt -s nullglob dotglob
directory_entries=("${directory}"/*)
shopt -u nullglob dotglob
if (( ${#directory_entries[@]} != ${#release_assets[@]} )); then
  echo "Expected exactly ${#release_assets[@]} top-level release assets; found ${#directory_entries[@]}" >&2
  exit 1
fi
for entry in "${directory_entries[@]}"; do
  name="${entry##*/}"
  if [[ -L "${entry}" || ! -f "${entry}" ]]; then
    echo "Release bundle entry is not a top-level regular file: ${name}" >&2
    exit 1
  fi
  expected=false
  for expected_name in "${release_assets[@]}"; do
    if [[ "${name}" == "${expected_name}" ]]; then
      expected=true
      break
    fi
  done
  if [[ "${expected}" != "true" ]]; then
    echo "Unexpected release asset: ${name}" >&2
    exit 1
  fi
done

for platform in "${platforms[@]}"; do
  zip="${directory}/codex-token-usage_${version}_${platform}.zip"
  sbom="${directory}/codex-token-usage_${version}_${platform}.spdx.json"
  [[ -s "${zip}" ]] || { echo "Missing release archive: ${zip}" >&2; exit 1; }
  [[ -s "${sbom}" ]] || { echo "Missing release SBOM: ${sbom}" >&2; exit 1; }
  ext="so"
  binary_name="codex-token-usage.so"

  if ! unzip -tqq "${zip}"; then
    echo "Release archive failed its CRC/integrity check: ${zip}" >&2
    exit 1
  fi
  if ! jq -e --arg binary "${binary_name}" '
    type == "object" and
    (.spdxVersion | type == "string" and test("^SPDX-2\\.[0-9]+$")) and
    .dataLicense == "CC0-1.0" and
    .SPDXID == "SPDXRef-DOCUMENT" and
    .name == $binary and
    (.documentNamespace | type == "string" and length > 0) and
    (.creationInfo | type == "object") and
    (.creationInfo.created | type == "string" and length > 0) and
    (.creationInfo.creators | type == "array" and length > 0) and
    (.packages | type == "array" and length > 0) and
    (.relationships | type == "array")
  ' "${sbom}" >/dev/null; then
    echo "Invalid or incomplete SPDX JSON: ${sbom}" >&2
    exit 1
  fi

  contents="${tmp_dir}/${platform}.contents"
  expected="${tmp_dir}/${platform}.expected"
  unzip -Z1 "${zip}" | LC_ALL=C sort > "${contents}"
  printf '%s\n' LICENSE THIRD_PARTY_NOTICES.md "${binary_name}" | LC_ALL=C sort > "${expected}"
  if ! diff -u "${expected}" "${contents}"; then
    echo "Unexpected archive contents: ${zip}" >&2
    exit 1
  fi

  extracted_binary="${tmp_dir}/${platform}.${ext}"
  unzip -p "${zip}" "${binary_name}" > "${extracted_binary}"
  if [[ ! -s "${extracted_binary}" ]]; then
    echo "Release archive contains an empty binary: ${zip}" >&2
    exit 1
  fi
  archive_sha256="$(sha256sum "${extracted_binary}" | awk '{print tolower($1)}')"
  sbom_sha256="$(
    jq -r --arg binary "${binary_name}" '
      [
        .packages[]?
        | select(.name == $binary)
        | .checksums[]?
        | select((.algorithm | ascii_upcase) == "SHA256")
        | .checksumValue
        | select(type == "string")
      ][0] // ""
    ' "${sbom}" | tr '[:upper:]' '[:lower:]'
  )"
  if [[ ! "${sbom_sha256}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "SPDX JSON has no SHA-256 checksum for ${binary_name}: ${sbom}" >&2
    exit 1
  fi
  if [[ "${archive_sha256}" != "${sbom_sha256}" ]]; then
    echo "SPDX checksum mismatch for ${binary_name}: archive=${archive_sha256} sbom=${sbom_sha256}" >&2
    exit 1
  fi
done

checksums="$(
  cd "${directory}"
  LC_ALL=C sha256sum -- "${release_assets[@]}" | LC_ALL=C sort -k2,2
)"
checksum_count="$(printf '%s\n' "${checksums}" | wc -l | tr -d ' ')"
if [[ "${checksum_count}" != "${#release_assets[@]}" ]]; then
  echo "Expected ${#release_assets[@]} checksum entries; generated ${checksum_count}" >&2
  exit 1
fi
printf '%s\n' "${checksums}" > "${directory}/checksums.txt"

echo "Verified ${#release_assets[@]} release assets and generated checksums.txt"
