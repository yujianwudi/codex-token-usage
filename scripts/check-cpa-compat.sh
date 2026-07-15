#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
lock_file="${script_dir}/cpa-compat.lock"
test_template="${script_dir}/cpa-compat/plugin_compat_test.go.txt"

if [[ ! -f "${lock_file}" ]]; then
  echo "CPA compatibility lock not found: ${lock_file}" >&2
  exit 1
fi
if [[ ! -f "${test_template}" ]]; then
  echo "CPA compatibility test template not found: ${test_template}" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "${lock_file}"

expected_commit="${CPA_COMPAT_COMMIT:-${CPA_COMMIT}}"
expected_repo="${CPA_COMPAT_REPOSITORY:-${CPA_REPOSITORY}}"
source_dir="${CPA_SOURCE_DIR:-}"

if [[ ! "${expected_commit}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Invalid pinned CPA commit: ${expected_commit}" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/codex-token-usage-cpa-compat.XXXXXX")"
cleanup() {
  rm -rf "${work_dir}"
}
trap cleanup EXIT

cpa_dir="${work_dir}/CLIProxyAPI"
if [[ -n "${source_dir}" ]]; then
  source_dir="$(cd "${source_dir}" && pwd)"
  resolved_commit="$(git -C "${source_dir}" rev-parse "${expected_commit}^{commit}")"
  if [[ "${resolved_commit}" != "${expected_commit}" ]]; then
    echo "CPA source does not contain pinned commit ${expected_commit}" >&2
    exit 1
  fi
  mkdir -p "${cpa_dir}"
  git -C "${source_dir}" archive "${expected_commit}" | tar -xf - -C "${cpa_dir}"
else
  git init -q "${cpa_dir}"
  git -C "${cpa_dir}" remote add origin "${expected_repo}"
  fetched=false
  for attempt in 1 2 3; do
    if git -C "${cpa_dir}" fetch -q --depth=1 origin "${expected_commit}"; then
      fetched=true
      break
    fi
    if (( attempt < 3 )); then
      sleep "$((attempt * 2))"
    fi
  done
  if [[ "${fetched}" != true ]]; then
    echo "Unable to fetch pinned CPA commit ${expected_commit} after 3 attempts" >&2
    exit 1
  fi
  git -C "${cpa_dir}" checkout -q --detach FETCH_HEAD
  resolved_commit="$(git -C "${cpa_dir}" rev-parse HEAD)"
  if [[ "${resolved_commit}" != "${expected_commit}" ]]; then
    echo "Fetched CPA commit ${resolved_commit}, expected ${expected_commit}" >&2
    exit 1
  fi
fi

if ! grep -Eq "ABIVersion[[:space:]]+uint32[[:space:]]*=[[:space:]]*${CPA_ABI_VERSION}" "${cpa_dir}/sdk/pluginabi/types.go"; then
  echo "Pinned CPA source no longer declares ABI version ${CPA_ABI_VERSION}" >&2
  exit 1
fi
if ! grep -Eq "SchemaVersion[[:space:]]+uint32[[:space:]]*=[[:space:]]*${CPA_SCHEMA_VERSION}" "${cpa_dir}/sdk/pluginabi/types.go"; then
  echo "Pinned CPA source no longer declares schema version ${CPA_SCHEMA_VERSION}" >&2
  exit 1
fi

case "$(uname -s)" in
  Linux)
    library="${work_dir}/codex-token-usage.so"
    nm_args=(-D --defined-only)
    ;;
  Darwin)
    library="${work_dir}/codex-token-usage.dylib"
    nm_args=(-gU)
    ;;
  *)
    echo "Real CPA dynamic-loader compatibility test supports Linux and Darwin" >&2
    exit 2
    ;;
esac

(
  cd "${repo_root}"
  CGO_ENABLED=1 go build -trimpath -buildmode=c-shared -o "${library}" .
)

exported_symbols="$(nm "${nm_args[@]}" "${library}")"
for symbol in cliproxy_plugin_init cliproxyPluginCall cliproxyPluginFree cliproxyPluginShutdown; do
  if ! grep -Eq "[[:space:]]_?${symbol}$" <<<"${exported_symbols}"; then
    echo "Missing plugin ABI export: ${symbol}" >&2
    exit 1
  fi
done

if command -v ldd >/dev/null 2>&1; then
  ldd -r "${library}" >/dev/null
fi

cp "${test_template}" "${cpa_dir}/internal/pluginhost/codex_token_usage_external_compat_test.go"

compat_usage_dir="${work_dir}/plugin-data"
compat_auth_dir="${work_dir}/auth"
mkdir -p "${compat_usage_dir}" "${compat_auth_dir}"

expected_version="$(sed -n 's/^[[:space:]]*pluginVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${repo_root}/main.go" | head -n 1)"
if [[ -z "${expected_version}" ]]; then
  echo "Unable to determine pluginVersion from main.go" >&2
  exit 1
fi

(
  cd "${cpa_dir}"
  CODEX_TOKEN_USAGE_PLUGIN_LIBRARY="${library}" \
  CODEX_TOKEN_USAGE_EXPECTED_VERSION="${expected_version}" \
  CODEX_TOKEN_USAGE_CPA_COMMIT="${expected_commit}" \
  CPA_TOKEN_USAGE_DIR="${compat_usage_dir}" \
  CPA_AUTH_DIR="${compat_auth_dir}" \
  GOWORK=off \
  go test -count=1 -run '^TestExternalCodexTokenUsageCompatibility$' -v ./internal/pluginhost
)

echo "CPA compatibility passed"
echo "repository=${expected_repo}"
echo "commit=${expected_commit}"
echo "abi=${CPA_ABI_VERSION} schema=${CPA_SCHEMA_VERSION}"
echo "plugin=${library}"
