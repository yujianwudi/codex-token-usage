#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
lock_file="${CPA_COMPAT_LOCK_FILE:-${script_dir}/cpa-compat.lock}"
test_template="${script_dir}/cpa-compat/plugin_compat_test.go.txt"
panic_control_template="${script_dir}/cpa-compat/panic_control_unix_test.go.txt"
cpa_sandbox_image="docker.io/library/golang:1.26.5-trixie@sha256:117e07f49461abb984fc8aef661432461ff43d06faa22c3b73af6a49ce325cb9"

if [[ ! -f "${lock_file}" ]]; then
  echo "CPA compatibility lock not found: ${lock_file}" >&2
  exit 1
fi
CPA_REPOSITORY=""
CPA_RELEASE_TAG=""
CPA_COMMIT=""
CPA_ABI_VERSION=""
CPA_SCHEMA_VERSION=""

load_compat_lock() {
  local line key value line_number=0 seen_keys=" "
  while IFS= read -r line || [[ -n "${line}" ]]; do
    line_number=$((line_number + 1))
    line="${line%$'\r'}"
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    if [[ "${line}" != *=* ]]; then
      echo "Invalid CPA compatibility lock entry at line ${line_number}" >&2
      return 1
    fi
    key="${line%%=*}"
    value="${line#*=}"
    if [[ "${seen_keys}" == *" ${key} "* ]]; then
      echo "Duplicate CPA compatibility lock key at line ${line_number}: ${key}" >&2
      return 1
    fi
    case "${key}" in
      CPA_REPOSITORY) CPA_REPOSITORY="${value}" ;;
      CPA_RELEASE_TAG) CPA_RELEASE_TAG="${value}" ;;
      CPA_COMMIT) CPA_COMMIT="${value}" ;;
      CPA_ABI_VERSION) CPA_ABI_VERSION="${value}" ;;
      CPA_SCHEMA_VERSION) CPA_SCHEMA_VERSION="${value}" ;;
      *)
        echo "Unknown CPA compatibility lock key at line ${line_number}: ${key}" >&2
        return 1
        ;;
    esac
    seen_keys+="${key} "
  done < "${lock_file}"
}

load_compat_lock

for required_key in CPA_REPOSITORY CPA_RELEASE_TAG CPA_COMMIT CPA_ABI_VERSION CPA_SCHEMA_VERSION; do
  if [[ -z "${!required_key}" ]]; then
    echo "Missing CPA compatibility lock key: ${required_key}" >&2
    exit 1
  fi
done

# shellcheck source=scripts/semver.sh
source "${script_dir}/semver.sh"

if [[ ! "${CPA_REPOSITORY}" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\.git$ ]]; then
  echo "Invalid pinned CPA repository: ${CPA_REPOSITORY}" >&2
  exit 1
fi
if [[ "${CPA_RELEASE_TAG}" != v* ]] || ! is_semver "${CPA_RELEASE_TAG#v}"; then
  echo "Invalid pinned CPA release tag: ${CPA_RELEASE_TAG}" >&2
  exit 1
fi
if [[ ! "${CPA_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Invalid pinned CPA commit: ${CPA_COMMIT}" >&2
  exit 1
fi
if [[ ! "${CPA_ABI_VERSION}" =~ ^[0-9]+$ || ! "${CPA_SCHEMA_VERSION}" =~ ^[0-9]+$ ]]; then
  echo "Invalid pinned CPA ABI/schema version" >&2
  exit 1
fi

expected_repo="${CPA_COMPAT_REPOSITORY:-${CPA_REPOSITORY}}"
source_dir="${CPA_SOURCE_DIR:-}"
channel="${CPA_COMPAT_CHANNEL:-}"
if [[ -z "${channel}" ]]; then
  if [[ -n "${CPA_COMPAT_COMMIT:-}" ]]; then
    channel="locked"
  else
    channel="latest-release"
  fi
fi

repo_slug="${expected_repo#https://github.com/}"
repo_slug="${repo_slug%.git}"
if [[ ! "${repo_slug}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "Cannot derive GitHub repository slug from CPA repository: ${expected_repo}" >&2
  exit 1
fi

github_api_get() {
  local endpoint="$1" api_base api_url token
  local -a curl_args
  if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required to resolve current CPA revisions" >&2
    return 1
  fi
  api_base="${CPA_COMPAT_GITHUB_API_URL:-${GITHUB_API_URL:-https://api.github.com}}"
  api_url="${api_base%/}/${endpoint#/}"
  curl_args=(
    --fail
    --location
    --silent
    --show-error
    --retry 3
    --retry-delay 2
    --connect-timeout 15
    --max-time 60
    --header "Accept: application/vnd.github+json"
    --header "X-GitHub-Api-Version: 2022-11-28"
  )
  token="${CPA_COMPAT_GITHUB_TOKEN:-}"
  if [[ -n "${token}" ]]; then
    curl_args+=(--header "Authorization: Bearer ${token}")
  fi
  if ! curl "${curl_args[@]}" "${api_url}"; then
    echo "GitHub API request failed: ${api_url}" >&2
    return 1
  fi
}

resolve_latest_release_tag() {
  local response
  if [[ -n "${CPA_COMPAT_LATEST_RELEASE_TAG:-}" ]]; then
    printf '%s\n' "${CPA_COMPAT_LATEST_RELEASE_TAG}"
    return 0
  fi
  if ! response="$(github_api_get "repos/${repo_slug}/releases/latest")"; then
    echo "Unable to query the latest published CPA release" >&2
    return 1
  fi
  if [[ "${response}" =~ \"tag_name\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  echo "Latest CPA release response did not contain tag_name" >&2
  return 1
}

resolve_github_commit() {
  local revision="$1" response
  if ! response="$(github_api_get "repos/${repo_slug}/commits/${revision}")"; then
    echo "Unable to resolve CPA revision to a commit: ${revision}" >&2
    return 1
  fi
  if [[ "${response}" =~ \"sha\"[[:space:]]*:[[:space:]]*\"([0-9a-f]{40})\" ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  echo "CPA revision response did not contain a commit SHA: ${revision}" >&2
  return 1
}

download_github_archive() {
  local commit="$1" destination="$2" archive_base archive_url token
  local -a archive_curl_args
  archive_base="${CPA_COMPAT_ARCHIVE_BASE_URL:-https://codeload.github.com}"
  archive_url="${archive_base%/}/${repo_slug}/tar.gz/${commit}"
  archive_curl_args=(
    --fail
    --location
    --silent
    --show-error
    --retry 3
    --retry-delay 2
    --connect-timeout 15
    --max-time 180
    --output "${destination}"
  )
  token="${CPA_COMPAT_GITHUB_TOKEN:-}"
  if [[ -n "${token}" ]]; then
    archive_curl_args+=(--header "Authorization: Bearer ${token}")
  fi
  if ! curl "${archive_curl_args[@]}" "${archive_url}"; then
    echo "Unable to download CPA source archive: ${archive_url}" >&2
    return 1
  fi
}

case "${channel}" in
  locked)
    expected_commit="${CPA_COMPAT_COMMIT:-${CPA_COMMIT}}"
    target_description="locked release ${CPA_RELEASE_TAG}"
    ;;
  latest-release)
    if [[ -n "${CPA_COMPAT_COMMIT:-}" ]]; then
      echo "CPA_COMPAT_COMMIT cannot override the latest-release channel" >&2
      exit 1
    fi
    latest_release_tag="$(resolve_latest_release_tag)"
    if [[ "${latest_release_tag}" != "${CPA_RELEASE_TAG}" ]]; then
      echo "CPA compatibility lock is stale: latest release is ${latest_release_tag}, lock contains ${CPA_RELEASE_TAG}" >&2
      exit 1
    fi
    latest_release_commit="$(resolve_github_commit "${latest_release_tag}")"
    if [[ "${latest_release_commit}" != "${CPA_COMMIT}" ]]; then
      echo "CPA compatibility lock is stale: ${latest_release_tag} resolves to ${latest_release_commit}, lock contains ${CPA_COMMIT}" >&2
      exit 1
    fi
    expected_commit="${CPA_COMMIT}"
    target_description="latest published release ${latest_release_tag}"
    ;;
  latest-main)
    if [[ -n "${CPA_COMPAT_COMMIT:-}" ]]; then
      echo "CPA_COMPAT_COMMIT cannot override the latest-main channel" >&2
      exit 1
    fi
    expected_commit="$(resolve_github_commit main)"
    target_description="latest main"
    ;;
  *)
    echo "Unsupported CPA compatibility channel: ${channel}" >&2
    exit 1
    ;;
esac

if [[ ! "${expected_commit}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Invalid resolved CPA commit: ${expected_commit}" >&2
  exit 1
fi

if [[ "${CPA_COMPAT_VALIDATE_ONLY:-false}" == "true" ]]; then
  echo "CPA compatibility target validated"
  echo "repository=${expected_repo}"
  echo "channel=${channel}"
  echo "target=${target_description}"
  echo "commit=${expected_commit}"
  echo "abi=${CPA_ABI_VERSION} schema=${CPA_SCHEMA_VERSION}"
  exit 0
fi

execution_mode="${CPA_COMPAT_EXECUTION_MODE:-host}"
case "${execution_mode}" in
  host | docker) ;;
  *)
    echo "Unsupported CPA compatibility execution mode: ${execution_mode}" >&2
    exit 2
    ;;
esac
if [[ "${GITHUB_ACTIONS:-false}" == "true" && "${execution_mode}" != "docker" ]]; then
  echo "GitHub Actions must execute external CPA tests in the Docker sandbox" >&2
  exit 2
fi

if [[ ! -f "${test_template}" ]]; then
  echo "CPA compatibility test template not found: ${test_template}" >&2
  exit 1
fi
if [[ ! -f "${panic_control_template}" ]]; then
  echo "CPA panic-control test template not found: ${panic_control_template}" >&2
  exit 1
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/codex-token-usage-cpa-compat.XXXXXX")"
cleanup() {
  chmod -R u+w "${work_dir}" 2>/dev/null || true
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
  cpa_archive="${work_dir}/CLIProxyAPI.tar.gz"
  mkdir -p "${cpa_dir}"
  download_github_archive "${expected_commit}" "${cpa_archive}"
  tar -xzf "${cpa_archive}" --strip-components=1 -C "${cpa_dir}"
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
    panic_library="${work_dir}/codex-token-usage-panic.so"
    nm_args=(-D --defined-only)
    ;;
  Darwin)
    library="${work_dir}/codex-token-usage.dylib"
    panic_library="${work_dir}/codex-token-usage-panic.dylib"
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
  CGO_ENABLED=1 go build -trimpath -tags=abi_panic_harness -buildmode=c-shared -o "${panic_library}" .
)

exported_symbols="$(nm "${nm_args[@]}" "${library}")"
for symbol in cliproxy_plugin_init cliproxyPluginCall cliproxyPluginFree cliproxyPluginShutdown; do
  if ! grep -Eq "[[:space:]]_?${symbol}$" <<<"${exported_symbols}"; then
    echo "Missing plugin ABI export: ${symbol}" >&2
    exit 1
  fi
done
for symbol in cliproxyTestSetPanicPoint cliproxyTestGetPanicPoint; do
  if grep -Eq "[[:space:]]_?${symbol}$" <<<"${exported_symbols}"; then
    echo "Release-compatible plugin unexpectedly exports panic-injection symbol ${symbol}" >&2
    exit 1
  fi
done
panic_exported_symbols="$(nm "${nm_args[@]}" "${panic_library}")"
for symbol in cliproxyTestSetPanicPoint cliproxyTestGetPanicPoint; do
  if ! grep -Eq "[[:space:]]_?${symbol}$" <<<"${panic_exported_symbols}"; then
    echo "Panic-injection compatibility library is missing ${symbol}" >&2
    exit 1
  fi
done

if command -v ldd >/dev/null 2>&1; then
  ldd -r "${library}" >/dev/null
  ldd -r "${panic_library}" >/dev/null
fi

cp "${test_template}" "${cpa_dir}/internal/pluginhost/codex_token_usage_external_compat_test.go"
cp "${panic_control_template}" "${cpa_dir}/internal/pluginhost/codex_token_usage_panic_control.go"

compat_usage_dir="${work_dir}/plugin-data"
compat_auth_dir="${work_dir}/auth"
compat_home="${work_dir}/home"
compat_gocache="${work_dir}/go-build-cache"
compat_gomodcache="${work_dir}/go-mod-cache"
compat_tmp="${work_dir}/tmp"
trusted_seed_gomodcache="$(go env GOMODCACHE)"
mkdir -p \
  "${compat_usage_dir}" \
  "${compat_auth_dir}" \
  "${compat_home}/.config" \
  "${compat_home}/.cache" \
  "${compat_gocache}" \
  "${compat_gomodcache}" \
  "${compat_tmp}" \
  "${work_dir}/gopath"

prefetch_proxy="${CPA_COMPAT_PREFETCH_GOPROXY:-https://proxy.golang.org}"
if [[ -d "${trusted_seed_gomodcache}/cache/download" ]]; then
  # The caller cache is exposed only to the trusted module downloader as a
  # read-only logical proxy source. External CPA tests receive only the copied
  # task-local cache and cannot read or mutate the caller cache.
  prefetch_proxy="file://${trusted_seed_gomodcache}/cache/download,${prefetch_proxy}"
fi
(
  cd "${cpa_dir}"
  env -i \
    PATH="${PATH}" \
    HOME="${compat_home}" \
    XDG_CONFIG_HOME="${compat_home}/.config" \
    XDG_CACHE_HOME="${compat_home}/.cache" \
    TMPDIR="${compat_tmp}" \
    GOTMPDIR="${compat_tmp}" \
    GOCACHE="${compat_gocache}" \
    GOMODCACHE="${compat_gomodcache}" \
    GOPATH="${work_dir}/gopath" \
    GOENV=off \
    GOTOOLCHAIN=local \
    CGO_ENABLED=1 \
    GOPROXY="${prefetch_proxy}" \
    GONOPROXY=none \
    GOSUMDB=off \
    GOFLAGS=-mod=readonly \
    'GOVCS=*:off' \
    GOWORK=off \
    go list -deps -test ./internal/pluginhost >/dev/null
)

expected_version="$(sed -n 's/^[[:space:]]*pluginVersion[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${repo_root}/main.go" | head -n 1)"
if [[ -z "${expected_version}" ]]; then
  echo "Unable to determine pluginVersion from main.go" >&2
  exit 1
fi

# Execute downloaded CPA source with a strict allowlist rather than trying to
# enumerate every possible credential variable. CI resolves revisions in an
# earlier token-bearing step, while this final step receives only the validated
# commit and no GitHub token. On GitHub Actions the test also runs in a pinned,
# networkless, non-root container that can see only this task's work directory;
# external init/TestMain code cannot modify the runner workspace, Actions post
# hooks, Docker socket, or shared Go caches.
external_test_env=(
  HOME="${compat_home}"
  XDG_CONFIG_HOME="${compat_home}/.config"
  XDG_CACHE_HOME="${compat_home}/.cache"
  TMPDIR="${compat_tmp}"
  GOTMPDIR="${compat_tmp}"
  GOCACHE="${compat_gocache}"
  GOMODCACHE="${compat_gomodcache}"
  GOPATH="${work_dir}/gopath"
  GOENV=off
  GOTOOLCHAIN=local
  CGO_ENABLED=1
  GOPROXY=off
  GONOPROXY=none
  GOSUMDB=off
  GOFLAGS=-mod=readonly
  'GOVCS=*:off'
  LANG=C
  LC_ALL=C
  GIT_CONFIG_GLOBAL=/dev/null
  GIT_CONFIG_NOSYSTEM=1
  CODEX_TOKEN_USAGE_PLUGIN_LIBRARY="${library}"
  CODEX_TOKEN_USAGE_PANIC_LIBRARY="${panic_library}"
  CODEX_TOKEN_USAGE_EXPECTED_VERSION="${expected_version}"
  CODEX_TOKEN_USAGE_CPA_COMMIT="${expected_commit}"
  CODEX_TOKEN_USAGE_COMPAT_SANDBOX=1
  CPA_TOKEN_USAGE_DIR="${compat_usage_dir}"
  CPA_AUTH_DIR="${compat_auth_dir}"
  GIT_TERMINAL_PROMPT=0
  GOWORK=off
)
external_test_command=(
  go test -count=1
  -run '^TestExternalCodexTokenUsage(Compatibility|PanicBoundary)$'
  -v ./internal/pluginhost
)

case "${execution_mode}" in
  host)
    (
      cd "${cpa_dir}"
      env -i PATH="${PATH}" "${external_test_env[@]}" "${external_test_command[@]}"
    )
    ;;
  docker)
    if ! command -v docker >/dev/null 2>&1; then
      echo "docker is required for sandboxed CPA source execution" >&2
      exit 2
    fi
    docker run --rm --pull=always \
      --network none \
      --read-only \
      --cap-drop ALL \
      --security-opt no-new-privileges \
      --pids-limit 512 \
      --memory 3g \
      --cpus 2 \
      --ulimit nofile=1024:1024 \
      --user "$(id -u):$(id -g)" \
      --tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m \
      --mount "type=bind,src=${work_dir},dst=${work_dir}" \
      --workdir "${cpa_dir}" \
      "${cpa_sandbox_image}" \
      env -i \
      PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin \
      "${external_test_env[@]}" \
      "${external_test_command[@]}"
    ;;
esac

echo "CPA compatibility passed"
echo "repository=${expected_repo}"
echo "channel=${channel}"
echo "target=${target_description}"
echo "commit=${expected_commit}"
echo "abi=${CPA_ABI_VERSION} schema=${CPA_SCHEMA_VERSION}"
echo "plugin=${library}"
