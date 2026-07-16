#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gate="${script_dir}/check-release-acceptance.sh"
waiver_gate="${script_dir}/check-release-waiver.sh"
accepted_commit="0123456789abcdef0123456789abcdef01234567"
other_commit="89abcdef0123456789abcdef0123456789abcdef"
accepted_digest="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
other_digest="89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
release_workflow="${script_dir}/../.github/workflows/release.yml"

if ! python3 - "${release_workflow}" <<'PY'
import pathlib
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
job_start = next((i for i, line in enumerate(lines) if line == "  release:"), None)
if job_start is None:
    raise SystemExit(1)
job_end = next(
    (i for i in range(job_start + 1, len(lines)) if lines[i].startswith("  ") and not lines[i].startswith("    ")),
    len(lines),
)
concurrency_start = next(
    (i for i in range(job_start + 1, job_end) if lines[i] == "    concurrency:"),
    None,
)
if concurrency_start is None:
    raise SystemExit(1)
concurrency_end = next(
    (i for i in range(concurrency_start + 1, job_end) if lines[i].startswith("    ") and not lines[i].startswith("      ")),
    job_end,
)
concurrency_lines = lines[concurrency_start + 1 : concurrency_end]
if sum(line == "      group: publish-stable" for line in concurrency_lines) != 1:
    raise SystemExit(1)
if sum(line == "      cancel-in-progress: false" for line in concurrency_lines) != 1:
    raise SystemExit(1)
def field_block(start, end, header, indent):
    header_line = " " * indent + header + ":"
    block_start = next((i for i in range(start, end) if lines[i] == header_line), None)
    if block_start is None:
        raise SystemExit(f"Release workflow is missing structured field: {header}")
    block_end = next(
        (
            i
            for i in range(block_start + 1, end)
            if lines[i].startswith(" " * indent)
            and not lines[i].startswith(" " * (indent + 2))
            and lines[i].strip()
        ),
        end,
    )
    return lines[block_start + 1 : block_end]


def job_bounds(name):
    start = next((i for i, line in enumerate(lines) if line == f"  {name}:"), None)
    if start is None:
        raise SystemExit(f"Release workflow is missing job: {name}")
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("  ") and not lines[i].startswith("    ")),
        len(lines),
    )
    return start, end


def job_steps(name):
    start, end = job_bounds(name)
    steps_start = next((i for i in range(start + 1, end) if lines[i] == "    steps:"), None)
    if steps_start is None:
        raise SystemExit(f"Release workflow job has no steps: {name}")
    starts = [i for i in range(steps_start + 1, end) if lines[i].startswith("      - ")]
    result = []
    for index, step_start in enumerate(starts):
        step_end = starts[index + 1] if index + 1 < len(starts) else end
        result.append(lines[step_start:step_end])
    return result


def step_scalar(step, key):
    prefix = f"        {key}:"
    values = [line[len(prefix):].strip() for line in step if line.startswith(prefix)]
    if len(values) > 1:
        raise SystemExit(f"Release workflow step repeats field: {key}")
    return values[0] if values else None


def step_name(step):
    first = step[0][len("      - "):]
    if first.startswith("name:"):
        return first[len("name:"):].strip()
    return step_scalar(step, "name")


def step_env(step):
    env_start = next((i for i, line in enumerate(step) if line == "        env:"), None)
    if env_start is None:
        return {}
    env = {}
    for line in step[env_start + 1 :]:
        if not line.startswith("          ") or line.startswith("            "):
            if line.strip():
                break
            continue
        key, separator, value = line.strip().partition(":")
        if not separator or not key:
            raise SystemExit("Release workflow contains a malformed step env entry")
        env[key] = value.strip()
    return env


def step_run(step):
    run_start = next((i for i, line in enumerate(step) if line.startswith("        run:")), None)
    if run_start is None:
        return ""
    inline = step[run_start][len("        run:"):].strip()
    if inline and inline != "|":
        return inline
    return "\n".join(line[10:] if line.startswith("          ") else line for line in step[run_start + 1 :])


dispatch_inputs = field_block(0, len(lines), "inputs", 4)
for input_name, required_fields in {
    "waive_independent_acceptance": ("        default: false", "        type: boolean"),
    "waiver_confirmation": ("        type: string",),
}.items():
    input_start = next((i for i, line in enumerate(dispatch_inputs) if line == f"      {input_name}:"), None)
    if input_start is None:
        raise SystemExit(f"Release workflow is missing owner-waiver input: {input_name}")
    input_end = next(
        (i for i in range(input_start + 1, len(dispatch_inputs)) if dispatch_inputs[i].startswith("      ") and not dispatch_inputs[i].startswith("        ")),
        len(dispatch_inputs),
    )
    input_lines = dispatch_inputs[input_start + 1 : input_end]
    for required in required_fields:
        if required not in input_lines:
            raise SystemExit(f"Release workflow input {input_name} is missing: {required.strip()}")

release_environment = field_block(job_start, job_end, "environment", 4)
expected_environment = "      name: ${{ inputs.waive_independent_acceptance && 'owner-waived-release' || 'independent-release' }}"
if release_environment.count(expected_environment) != 1:
    raise SystemExit("Release workflow must route owner waivers through owner-waived-release")

if any(line == "  build-other:" for line in lines):
    raise SystemExit("Release workflow must not publish non-Linux platform builds")
build_linux_start, build_linux_end = job_bounds("build-linux")
release_arches = [
    line.strip()[len("- goarch: "):]
    for line in lines[build_linux_start:build_linux_end]
    if line.strip().startswith("- goarch: ")
]
if sorted(release_arches) != ["amd64", "arm64"]:
    raise SystemExit(f"Release workflow Linux architecture matrix changed: {sorted(release_arches)}")
verify_start, verify_end = job_bounds("verify-assets")
verify_needs = {
    line.strip()
    for line in field_block(verify_start, verify_end, "needs", 4)
    if line.strip()
}
if verify_needs != {"- validate", "- build-linux"}:
    raise SystemExit(f"Release asset verification has unexpected dependencies: {sorted(verify_needs)}")
if lines.count("          pattern: cpa-plugin-build-linux-*") != 1:
    raise SystemExit("Release asset download must be restricted to Linux build artifacts")
for subject in (
    "release-assets/codex-token-usage_${{ needs.validate.outputs.version }}_linux_amd64.zip",
    "release-assets/codex-token-usage_${{ needs.validate.outputs.version }}_linux_arm64.zip",
    "release-assets/codex-token-usage_${{ needs.validate.outputs.version }}_linux_amd64.spdx.json",
    "release-assets/codex-token-usage_${{ needs.validate.outputs.version }}_linux_arm64.spdx.json",
    "release-assets/checksums.txt",
):
    if lines.count(f"            {subject}") != 1:
        raise SystemExit(f"Release provenance must name exactly one Linux bundle subject: {subject}")
if "            release-assets/*.zip" in lines or "            release-assets/*.spdx.json" in lines:
    raise SystemExit("Release provenance must not use open-ended asset globs")

validate_steps = job_steps("validate")
release_steps = job_steps("release")
all_steps = validate_steps + release_steps

validate_waiver = [step for step in validate_steps if step_name(step) == "Validate version, source, and unused release tag"]
if len(validate_waiver) != 1:
    raise SystemExit("Release workflow must contain one structured pre-build waiver validation step")
validate_env = step_env(validate_waiver[0])
validate_run = step_run(validate_waiver[0])
if validate_env.get("WAIVE_INDEPENDENT_ACCEPTANCE") != "${{ inputs.waive_independent_acceptance }}":
    raise SystemExit("Pre-build waiver validation is not bound to waive_independent_acceptance")
if validate_env.get("WAIVER_CONFIRMATION") != "${{ inputs.waiver_confirmation }}":
    raise SystemExit("Pre-build waiver validation is not bound to waiver_confirmation")
for required in (
    '"${source_commit}" != "${main_commit}"',
    "bash scripts/check-release-waiver.sh",
):
    if required not in validate_run:
        raise SystemExit(f"Pre-build waiver validation is missing: {required}")

acceptance_steps = [step for step in release_steps if step_name(step) == "Verify independent second-machine acceptance authorization"]
if len(acceptance_steps) != 1 or step_scalar(acceptance_steps[0], "if") != "${{ !inputs.waive_independent_acceptance }}":
    raise SystemExit("Independent acceptance must run only when the owner waiver is disabled")
acceptance_env = step_env(acceptance_steps[0])
if acceptance_env.get("CPA_INDEPENDENT_ACCEPTED_RELEASES") != "${{ vars.CPA_INDEPENDENT_ACCEPTED_RELEASES }}":
    raise SystemExit("Independent acceptance is not bound to the protected Environment variable")
if "bash scripts/check-release-acceptance.sh" not in step_run(acceptance_steps[0]):
    raise SystemExit("Independent acceptance step does not invoke its gate")

waiver_steps = [step for step in release_steps if step_name(step) == "Record repository-owner second-machine waiver"]
if len(waiver_steps) != 1 or step_scalar(waiver_steps[0], "if") != "${{ inputs.waive_independent_acceptance }}":
    raise SystemExit("Owner waiver must run only when explicitly requested")
waiver_env = step_env(waiver_steps[0])
if waiver_env.get("WAIVER_CONFIRMATION") != "${{ inputs.waiver_confirmation }}":
    raise SystemExit("Publication waiver is not bound to waiver_confirmation")
waiver_run = step_run(waiver_steps[0])
for required in (
    "bash scripts/check-release-waiver.sh",
    "Independent second-machine acceptance was explicitly waived by repository owner",
):
    if required not in waiver_run:
        raise SystemExit(f"Publication waiver step is missing: {required}")

publication_state_steps = [step for step in release_steps if step_name(step) == "Inspect resumable publication state"]
if len(publication_state_steps) != 1:
    raise SystemExit("Release workflow must contain one resumable publication-state step")
publication_state_run = step_run(publication_state_steps[0])
for required in (
    'gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100"',
    "[.[][] | select(.tag_name == $tag)]",
    "Multiple Releases use tag ${RELEASE_TAG}; refusing ambiguous recovery",
):
    if required not in publication_state_run:
        raise SystemExit(f"Publication-state recovery is not draft-safe: {required}")
if 'release_status="$(github_api_status "repos/${GITHUB_REPOSITORY}/releases/tags/${RELEASE_TAG}")"' in publication_state_run:
    raise SystemExit("Publication-state recovery must not query the draft-blind release-by-tag endpoint")

publication_steps = [step for step in release_steps if step_name(step) == "Create, resume, and verify release publication"]
if len(publication_steps) != 1:
    raise SystemExit("Release workflow must contain one publication step")
publication_run = step_run(publication_steps[0])
for required in (
    'gh release view "${RELEASE_TAG}" --json body',
    "--jq '.body // \"\"'",
):
    if required not in publication_run:
        raise SystemExit(f"Draft Release body lookup is not resumable: {required}")

previous_release_steps = [step for step in release_steps if step_name(step) == "Resolve previous published release"]
if len(previous_release_steps) != 1 or "bash scripts/select-previous-release-tag.sh" not in step_run(previous_release_steps[0]):
    raise SystemExit("Stable publication is missing its serialized version-order gate")

if sum(step_run(step).count("bash scripts/check-release-waiver.sh") for step in all_steps) != 2:
    raise SystemExit("Release workflow must validate the owner waiver before build and before publication")
PY
then
	echo "Stable Release publication is not serialized through one repository-wide concurrency lane" >&2
	exit 1
fi

if CPA_INDEPENDENT_ACCEPTED_RELEASES="" bash "${gate}" v0.1.39 "${accepted_commit}" "${accepted_digest}" >/dev/null 2>&1; then
	echo "Acceptance gate allowed an empty authorization list" >&2
	exit 1
fi

if CPA_INDEPENDENT_ACCEPTED_RELEASES="v0.1.38@${accepted_commit}@${accepted_digest}, v0.1.40@${accepted_commit}@${accepted_digest}" bash "${gate}" v0.1.39 "${accepted_commit}" "${accepted_digest}" >/dev/null 2>&1; then
	echo "Acceptance gate allowed a different tag" >&2
	exit 1
fi

if CPA_INDEPENDENT_ACCEPTED_RELEASES="v0.1.39@${other_commit}@${accepted_digest}" bash "${gate}" v0.1.39 "${accepted_commit}" "${accepted_digest}" >/dev/null 2>&1; then
	echo "Acceptance gate allowed the right tag on an unaccepted commit" >&2
	exit 1
fi

if CPA_INDEPENDENT_ACCEPTED_RELEASES="v0.1.39@${accepted_commit}@${other_digest}" bash "${gate}" v0.1.39 "${accepted_commit}" "${accepted_digest}" >/dev/null 2>&1; then
	echo "Acceptance gate allowed an unaccepted candidate bundle digest" >&2
	exit 1
fi

if CPA_INDEPENDENT_ACCEPTED_RELEASES="v0.1.39@${accepted_commit}" bash "${gate}" v0.1.39 "${accepted_commit}" "${accepted_digest}" >/dev/null 2>&1; then
	echo "Acceptance gate allowed a legacy tag@commit authorization" >&2
	exit 1
fi

CPA_INDEPENDENT_ACCEPTED_RELEASES=$'v0.1.38@0123456789abcdef0123456789abcdef01234567@0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,\nv0.1.39@0123456789abcdef0123456789abcdef01234567@0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\tv0.1.40@0123456789abcdef0123456789abcdef01234567@0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
	bash "${gate}" v0.1.39 "${accepted_commit}" "${accepted_digest}" >/dev/null

if CPA_INDEPENDENT_ACCEPTED_RELEASES="v0.1.39-rc.1@${accepted_commit}@${accepted_digest}" bash "${gate}" v0.1.39-rc.1 "${accepted_commit}" "${accepted_digest}" >/dev/null 2>&1; then
	echo "Acceptance gate allowed a prerelease version" >&2
	exit 1
fi

if CPA_INDEPENDENT_ACCEPTED_RELEASES="v0.1.39+acceptance.2@${accepted_commit}@${accepted_digest}" bash "${gate}" v0.1.39+acceptance.2 "${accepted_commit}" "${accepted_digest}" >/dev/null 2>&1; then
	echo "Acceptance gate allowed build metadata on a stable publication" >&2
	exit 1
fi

if CPA_INDEPENDENT_ACCEPTED_RELEASES="v0.1.39@${accepted_commit}@${accepted_digest}" bash "${gate}" 0.1.39 "${accepted_commit}" "${accepted_digest}" >/dev/null 2>&1; then
	echo "Acceptance gate allowed a non-tag version" >&2
	exit 1
fi

if CPA_INDEPENDENT_ACCEPTED_RELEASES="v0.1.39@${accepted_commit}@${accepted_digest}" bash "${gate}" v0.1.39 short "${accepted_digest}" >/dev/null 2>&1; then
	echo "Acceptance gate allowed a malformed commit" >&2
	exit 1
fi

if CPA_INDEPENDENT_ACCEPTED_RELEASES="v0.1.39@${accepted_commit}@${accepted_digest}" bash "${gate}" v0.1.39 "${accepted_commit}" short >/dev/null 2>&1; then
	echo "Acceptance gate allowed a malformed candidate bundle digest" >&2
	exit 1
fi

if CPA_INDEPENDENT_ACCEPTED_RELEASES="v0.1.39@${accepted_commit}@${accepted_digest}" bash "${gate}" v0.1.39 "${accepted_commit}" "${accepted_digest^^}" >/dev/null 2>&1; then
	echo "Acceptance gate allowed a non-canonical uppercase candidate bundle digest" >&2
	exit 1
fi

if ! bash "${waiver_gate}" v0.1.39 yujianwudi yujianwudi WAIVE_SECOND_MACHINE_v0.1.39 >/dev/null; then
	echo "Owner waiver gate rejected the exact repository-owner confirmation" >&2
	exit 1
fi
if bash "${waiver_gate}" v0.1.39 contributor yujianwudi WAIVE_SECOND_MACHINE_v0.1.39 >/dev/null 2>&1; then
	echo "Owner waiver gate accepted a non-owner actor" >&2
	exit 1
fi
if bash "${waiver_gate}" v0.1.39 yujianwudi yujianwudi WAIVE_SECOND_MACHINE_v0.1.40 >/dev/null 2>&1; then
	echo "Owner waiver gate accepted a confirmation for a different version" >&2
	exit 1
fi
