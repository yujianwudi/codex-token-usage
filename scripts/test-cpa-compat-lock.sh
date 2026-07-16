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

github_sandbox_error="${work_dir}/github-sandbox.err"
if GITHUB_ACTIONS=true \
  CPA_COMPAT_CHANNEL=locked \
  bash scripts/check-cpa-compat.sh >"${work_dir}/github-sandbox.out" 2>"${github_sandbox_error}"; then
  echo "GitHub Actions compatibility execution was allowed without the Docker sandbox" >&2
  exit 1
fi
if ! grep -Fq "GitHub Actions must execute external CPA tests in the Docker sandbox" "${github_sandbox_error}"; then
  echo "GitHub Actions compatibility execution did not fail at the sandbox gate" >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def job_block(path: str, job_id: str) -> list[str]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    jobs = lines.index("jobs:")
    start = next(i for i in range(jobs + 1, len(lines)) if lines[i] == f"  {job_id}:")
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("  ") and not lines[i].startswith("    ")),
        len(lines),
    )
    return lines[start:end]


def mapping_block(lines: list[str], header: str) -> dict[str, str]:
    try:
        start = lines.index(header)
    except ValueError:
        return {}
    header_indent = len(header) - len(header.lstrip())
    entry_indent = " " * (header_indent + 2)
    result: dict[str, str] = {}
    for line in lines[start + 1 :]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= header_indent:
            break
        if indent != header_indent + 2 or ":" not in line[len(entry_indent):]:
            continue
        key, value = line[len(entry_indent):].split(":", 1)
        result[key.strip()] = unquote(value)
    return result


def parse_steps(job: list[str]) -> list[dict[str, object]]:
    steps_start = job.index("    steps:")
    starts = [i for i in range(steps_start + 1, len(job)) if job[i].startswith("      - ")]
    steps: list[dict[str, object]] = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(job)
        block = job[start:end]
        step: dict[str, object] = {"env": {}, "lines": block}

        first = block[0][8:]
        if ":" in first:
            key, value = first.split(":", 1)
            step[key.strip()] = unquote(value)

        i = 1
        while i < len(block):
            line = block[i]
            if not line.startswith("        ") or line.startswith("          ") or ":" not in line[8:]:
                i += 1
                continue
            key, value = line[8:].split(":", 1)
            key = key.strip()
            value = value.strip()
            if key == "env" and value == "":
                env: dict[str, str] = {}
                i += 1
                while i < len(block) and block[i].startswith("          ") and not block[i].startswith("            "):
                    entry = block[i][10:]
                    if ":" in entry:
                        env_key, env_value = entry.split(":", 1)
                        env[env_key.strip()] = unquote(env_value)
                    i += 1
                step["env"] = env
                continue
            if key == "run" and value in {"|", ">", "|-", ">-"}:
                i += 1
                run_lines: list[str] = []
                while i < len(block) and block[i].startswith("          "):
                    run_lines.append(block[i][10:])
                    i += 1
                step["run"] = "\n".join(run_lines)
                continue
            step[key] = unquote(value)
            i += 1
        steps.append(step)
    return steps


def named_step(steps: list[dict[str, object]], name: str) -> tuple[int, dict[str, object]]:
    matches = [(i, step) for i, step in enumerate(steps) if step.get("name") == name]
    if len(matches) != 1:
        raise SystemExit(f"expected exactly one workflow step named {name!r}")
    return matches[0]


checks = [
    (".github/workflows/ci.yml", "test", "latest-release", "Resolve latest published CLIProxyAPI revision", "Verify resolved CLIProxyAPI compatibility without credentials"),
    (".github/workflows/release.yml", "source-security", "latest-release", "Resolve latest published CLIProxyAPI revision", "Verify resolved CLIProxyAPI compatibility without credentials"),
    (".github/workflows/cpa-compat.yml", "compatibility", "${{ matrix.channel }}", "Resolve CPA revision", "Dynamically load plugin in resolved CPA without credentials"),
]
for path, job_id, expected_channel, resolver_name, executor_name in checks:
    workflow_lines = Path(path).read_text(encoding="utf-8").splitlines()
    job = job_block(path, job_id)
    steps = parse_steps(job)
    resolver_index, resolver = named_step(steps, resolver_name)
    executor_index, executor = named_step(steps, executor_name)
    if resolver_index >= executor_index:
        raise SystemExit(f"{path}: CPA resolver does not precede source execution")
    if executor_index != resolver_index + 1:
        raise SystemExit(f"{path}: another step runs between CPA resolution and source execution")
    if executor_index != len(steps) - 1:
        raise SystemExit(f"{path}: CPA compatibility is no longer the final declared workflow step")

    resolver_env = resolver.get("env")
    executor_env = executor.get("env")
    if not isinstance(resolver_env, dict) or not isinstance(executor_env, dict):
        raise SystemExit(f"{path}: CPA steps do not contain parsed environment mappings")
    if resolver_env.get("CPA_COMPAT_CHANNEL") != expected_channel:
        raise SystemExit(f"{path}: CPA resolver targets the wrong channel")
    if resolver_env.get("CPA_COMPAT_GITHUB_TOKEN") != "${{ github.token }}" or resolver_env.get("CPA_COMPAT_VALIDATE_ONLY") != "true":
        raise SystemExit(f"{path}: CPA resolver is not a validate-only token-bearing step")
    resolver_run = resolver.get("run")
    if not isinstance(resolver_run, str) or "bash scripts/check-cpa-compat.sh" not in resolver_run or 'echo "commit=${commit}" >> "${GITHUB_OUTPUT}"' not in resolver_run:
        raise SystemExit(f"{path}: CPA resolver does not publish its validated commit")
    if executor_env.get("CPA_COMPAT_CHANNEL") != "locked" or executor_env.get("CPA_COMPAT_COMMIT") != "${{ steps.resolve_cpa.outputs.commit }}":
        raise SystemExit(f"{path}: CPA executor does not consume only the resolved commit")
    if executor_env.get("CPA_COMPAT_EXECUTION_MODE") != "docker":
        raise SystemExit(f"{path}: CPA executor does not require the Docker sandbox")
    if executor.get("run") != "bash scripts/check-cpa-compat.sh":
        raise SystemExit(f"{path}: CPA executor runs an unexpected command")
    inherited_env = mapping_block(workflow_lines, "env:")
    inherited_env.update(mapping_block(job, "    env:"))
    inherited_env.update(executor_env)
    for key, value in inherited_env.items():
        upper_key = key.upper()
        if any(marker in upper_key for marker in ("TOKEN", "SECRET", "PASSWORD", "ASKPASS", "SSH_AUTH")):
            raise SystemExit(f"{path}: CPA executor inherits credential-like workflow environment key {key}")
        if any(marker in str(value) for marker in ("github.token", "secrets.", "vars.")):
            raise SystemExit(f"{path}: CPA executor inherits workflow credential expression in {key}")

compat_script = Path("scripts/check-cpa-compat.sh").read_text(encoding="utf-8")
prefetch_marker = 'go list -deps -test ./internal/pluginhost >/dev/null'
if compat_script.count(prefetch_marker) != 1:
    raise SystemExit("CPA compatibility must prefetch only the pluginhost test dependency closure")
if "go mod download all" in compat_script:
    raise SystemExit("CPA compatibility must not download unrelated modules from the CPA build list")
prefetch_start = compat_script.index('prefetch_proxy="${CPA_COMPAT_PREFETCH_GOPROXY:-https://proxy.golang.org}"')
prefetch_end = compat_script.index(prefetch_marker, prefetch_start) + len(prefetch_marker)
executor_start = compat_script.index("external_test_env=(", prefetch_end)
prefetch = compat_script[prefetch_start:prefetch_end]
executor = compat_script[executor_start:]
for required in (
    'GOCACHE="${compat_gocache}"',
    'GOMODCACHE="${compat_gomodcache}"',
    'TMPDIR="${compat_tmp}"',
    'GOTMPDIR="${compat_tmp}"',
    "GOFLAGS=-mod=readonly",
    "'GOVCS=*:off'",
):
    if required not in prefetch:
        raise SystemExit(f"CPA dependency prefetch is missing isolated setting: {required}")
for required in (
    'GOCACHE="${compat_gocache}"',
    'GOMODCACHE="${compat_gomodcache}"',
    'TMPDIR="${compat_tmp}"',
    'GOTMPDIR="${compat_tmp}"',
    "GOPROXY=off",
    "GOFLAGS=-mod=readonly",
):
    if required not in executor:
        raise SystemExit(f"CPA source execution is missing isolated setting: {required}")
if 'chmod -R u+w "${work_dir}"' not in compat_script:
    raise SystemExit("CPA compatibility cleanup cannot remove read-only module cache entries")
for required in (
    'cpa_sandbox_image="docker.io/library/golang:1.26.5-trixie@sha256:',
    '"${GITHUB_ACTIONS:-false}" == "true" && "${execution_mode}" != "docker"',
    "--network none",
    "--read-only",
    "--cap-drop ALL",
    "--security-opt no-new-privileges",
    '--user "$(id -u):$(id -g)"',
    '--mount "type=bind,src=${work_dir},dst=${work_dir}"',
):
    if required not in executor and required not in compat_script:
        raise SystemExit(f"CPA Docker sandbox is missing control: {required}")
if "docker.sock" in compat_script:
    raise SystemExit("CPA Docker sandbox must not mount the host Docker socket")
PY

echo "CPA compatibility lock parsing tests passed"
