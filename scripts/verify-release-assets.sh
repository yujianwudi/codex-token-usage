#!/usr/bin/env bash
set -euo pipefail

version="${1:?usage: verify-release-assets.sh VERSION DIRECTORY}"
directory="${2:?usage: verify-release-assets.sh VERSION DIRECTORY}"
if [[ ! -d "${directory}" ]]; then
  echo "Release asset directory not found: ${directory}" >&2
  exit 1
fi

platforms=(
  linux_amd64
  linux_arm64
  darwin_amd64
  darwin_arm64
  windows_amd64
)
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

for platform in "${platforms[@]}"; do
  zip="${directory}/codex-token-usage_${version}_${platform}.zip"
  sbom="${directory}/codex-token-usage_${version}_${platform}.spdx.json"
  [[ -s "${zip}" ]] || { echo "Missing release archive: ${zip}" >&2; exit 1; }
  [[ -s "${sbom}" ]] || { echo "Missing release SBOM: ${sbom}" >&2; exit 1; }
  contents="${tmp_dir}/${platform}.contents"
  expected="${tmp_dir}/${platform}.expected"
  unzip -Z1 "${zip}" | LC_ALL=C sort > "${contents}"
  printf '%s\n' LICENSE THIRD_PARTY_NOTICES.md "codex-token-usage.$(
    case "${platform}" in
      windows_*) printf 'dll' ;;
      darwin_*) printf 'dylib' ;;
      *) printf 'so' ;;
    esac
  )" | LC_ALL=C sort > "${expected}"
  if ! diff -u "${expected}" "${contents}"; then
    echo "Unexpected archive contents: ${zip}" >&2
    exit 1
  fi
done

zip_count="$(find "${directory}" -maxdepth 1 -type f -name '*.zip' | wc -l | tr -d ' ')"
sbom_count="$(find "${directory}" -maxdepth 1 -type f -name '*.spdx.json' | wc -l | tr -d ' ')"
if [[ "${zip_count}" != "${#platforms[@]}" || "${sbom_count}" != "${#platforms[@]}" ]]; then
  echo "Expected ${#platforms[@]} archives and SBOMs; found ${zip_count} archives and ${sbom_count} SBOMs" >&2
  exit 1
fi

(
  cd "${directory}"
  LC_ALL=C sha256sum -- *.zip *.spdx.json | LC_ALL=C sort -k2,2 > checksums.txt
)

echo "Verified ${zip_count} release archives and ${sbom_count} SBOMs"
