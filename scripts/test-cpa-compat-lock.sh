#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! git check-attr eol -- scripts/cpa-compat.lock | grep -Fq 'eol: lf'; then
  echo "CPA compatibility lock is not forced to LF by .gitattributes" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/codex-token-usage-cpa-lock-test.XXXXXX")"
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

lock_file="${work_dir}/cpa-compat.lock"
expected_tag="$(awk -F= '$1 == "CPA_RELEASE_TAG" { print $2; exit }' scripts/cpa-compat.lock | tr -d '\r')"
expected_commit="$(awk -F= '$1 == "CPA_COMMIT" { print $2; exit }' scripts/cpa-compat.lock | tr -d '\r')"
while IFS= read -r line || [[ -n "${line}" ]]; do
  printf '%s\r\n' "${line%$'\r'}"
done < scripts/cpa-compat.lock > "${lock_file}"

output="$(
  CPA_COMPAT_LOCK_FILE="${lock_file}" \
  CPA_COMPAT_CHANNEL=locked \
  CPA_COMPAT_VALIDATE_ONLY=true \
    bash scripts/check-cpa-compat.sh
)"
grep -Fqx 'CPA compatibility target validated' <<< "${output}"
grep -Fqx 'channel=locked' <<< "${output}"
grep -Fqx "commit=${expected_commit}" <<< "${output}"

if CPA_COMPAT_LOCK_FILE="${lock_file}" \
  CPA_COMPAT_CHANNEL=latest-release \
  CPA_COMPAT_LATEST_RELEASE_TAG="${expected_tag}-stale" \
  CPA_COMPAT_VALIDATE_ONLY=true \
  bash scripts/check-cpa-compat.sh >/dev/null 2>&1; then
  echo "CPA compatibility gate accepted a stale latest-release lock" >&2
  exit 1
fi

cp scripts/cpa-compat.lock "${lock_file}"
printf '%s\n' 'CPA_UNEXPECTED=value' >> "${lock_file}"
if CPA_COMPAT_LOCK_FILE="${lock_file}" \
  CPA_COMPAT_CHANNEL=locked \
  CPA_COMPAT_VALIDATE_ONLY=true \
  bash scripts/check-cpa-compat.sh >/dev/null 2>&1; then
  echo "CPA compatibility lock accepted an unknown key" >&2
  exit 1
fi

cp scripts/cpa-compat.lock "${lock_file}"
printf 'CPA_COMMIT=%s\n' "${expected_commit}" >> "${lock_file}"
if CPA_COMPAT_LOCK_FILE="${lock_file}" \
  CPA_COMPAT_CHANNEL=locked \
  CPA_COMPAT_VALIDATE_ONLY=true \
  bash scripts/check-cpa-compat.sh >/dev/null 2>&1; then
  echo "CPA compatibility lock accepted a duplicate key" >&2
  exit 1
fi

echo "CPA compatibility lock parsing tests passed"
