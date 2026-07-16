# Release candidate acceptance runbook

This runbook keeps independent acceptance attached to the exact files that are later published. A Release workflow run builds the platform archives and SPDX files once, verifies the closed asset set, generates `checksums.txt`, and records the SHA-256 digest of that manifest. The normal publish job then waits at the `independent-release` Environment. It does not rebuild the plugin. A separately audited repository-owner waiver exists for emergencies and is documented below; it never fabricates an acceptance report.

Do not merge the candidate or create the version tag before independent acceptance finishes. After acceptance, promote the exact tested commit to `main` without changing its SHA. The workflow creates the annotated tag only after the accepted version, source commit, and bundle digest have all been authorized.

## Repository setup

Configure these controls before starting a candidate:

- Create an `independent-release` Environment with required reviewers. Prevent the candidate author from being the only reviewer where the repository plan supports that control.
- Keep only one stable candidate in the approval lane at a time. GitHub concurrency preserves the running publication but keeps at most one pending run; starting a third stable candidate can replace an older pending candidate even with `cancel-in-progress: false`.
- Allow reviewed candidate branches in the Environment deployment policy. The workflow run keeps its candidate-branch identity after the accepted commit is promoted to `main`; keep that branch until publication completes.
- Create the non-secret Environment variable `CPA_INDEPENDENT_ACCEPTED_RELEASES`. Keep it empty until a second-machine report accepts a candidate.
- Restrict `v*` tag creation and direct GitHub Release publication so the Release workflow is the only normal publication path.
- Keep Actions artifact retention at least as long as the independent test window. The candidate bundle in this workflow is retained for 30 days.

The variable is a whitespace- or comma-separated allowlist. Every entry has this exact canonical format:

```text
vX.Y.Z@<40 lowercase hex source commit>@<64 lowercase hex bundle digest>
```

Legacy `tag@commit` entries do not authorize publication.

## 1. Start and identify the candidate run

Dispatch `.github/workflows/release.yml` from the unmerged candidate branch and provide a stable `MAJOR.MINOR.PATCH` source version. The workflow rejects `main`, tag refs, prerelease/build metadata, a candidate that is not a fast-forward descendant of the current `main`, a source/version mismatch, or an existing version tag.

```bash
VERSION=X.Y.Z
CANDIDATE_BRANCH=<unmerged candidate branch>
gh workflow run release.yml --ref "${CANDIDATE_BRANCH}" -f version="${VERSION}"
gh run list \
  --workflow release.yml \
  --event workflow_dispatch \
  --branch "${CANDIDATE_BRANCH}" \
  --limit 20 \
  --json databaseId,createdAt,headBranch,headSha,status,url
```

Select the run started for this version from its Actions URL and set its numeric ID explicitly. Do not assume that the newest run is the right candidate when multiple releases are active.

```bash
RUN_ID=<release workflow run id>
gh run view "${RUN_ID}" --json event,headBranch,headSha,status,url
```

Confirm that `event` is `workflow_dispatch`, `headBranch` is the unmerged candidate branch, and `headSha` is the commit submitted for review. Wait until the `Verify complete release bundle` job succeeds and its summary says that the release candidate is ready. The publish job should be waiting for the `independent-release` Environment at this point; `main` must still be unchanged and no version tag should exist.

## 2. Download and verify the frozen bundle

Use a clean directory on the independent machine. GitHub makes the uploaded artifact available after its upload step even while the publish job is waiting for Environment approval.

```bash
TAG="v${VERSION#v}"
HEAD_SHA="$(gh run view "${RUN_ID}" --json headSha --jq .headSha)"
CANDIDATE_DIR="candidate-${RUN_ID}"
test ! -e "${CANDIDATE_DIR}"

gh run download "${RUN_ID}" \
  --name "cpa-plugin-release-${VERSION#v}" \
  --dir "${CANDIDATE_DIR}"

(
  cd "${CANDIDATE_DIR}"
  expected_names="$({ awk '{print $2}' checksums.txt; echo checksums.txt; } | LC_ALL=C sort)"
  actual_names="$(find . -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
  test "$(printf '%s\n' "${actual_names}" | wc -l | tr -d ' ')" = 11
  test "${actual_names}" = "${expected_names}"
  while IFS= read -r file; do
    test -f "${file}"
    test ! -L "${file}"
  done <<< "${expected_names}"
  sha256sum --check --strict checksums.txt
)
BUNDLE_DIGEST="$(sha256sum "${CANDIDATE_DIR}/checksums.txt" | awk '{print tolower($1)}')"
printf 'tag=%s\ncommit=%s\nbundle_digest=%s\n' "${TAG}" "${HEAD_SHA}" "${BUNDLE_DIGEST}"
```

Compare `BUNDLE_DIGEST` with the digest in the `Verify complete release bundle` job summary. The manifest covers all five platform archives and all five SPDX JSON files. A missing, extra, renamed, or changed release asset requires rejection and a new workflow run.

Also record the benchmark artifact named `release-scheduler-benchmarks-<commit>`. The Release workflow applies the same benchmark budget used by CI before building the candidate.

## 3. Test against the latest published CLIProxyAPI

Check out `HEAD_SHA` on the independent machine and run the online compatibility gate:

```bash
git checkout --detach "${HEAD_SHA}"
CPA_COMPAT_CHANNEL=latest-release bash scripts/check-cpa-compat.sh
```

This command resolves GitHub's latest published `router-for-me/CLIProxyAPI` release, requires `scripts/cpa-compat.lock` to name that exact tag and commit, builds against that source, and exercises the real CPA loader. It fails closed when the audited lock is stale. The publish job repeats the online latest-release/lock validation after Environment approval and immediately before any tag mutation, without rebuilding the candidate.

The real-loader gate covers Host registration and reconfiguration, management and auth callbacks, scheduling, usage adaptation, panic isolation, and two independent CPA Host processes competing for a shared SQLite reservation limit of one. The two-process barrier must produce exactly one successful reservation and one saturated result. The repository's internal stress gate separately exercises the heavier 2/4/8-process reservation matrix and crash/lock recovery.

The automated loader does not replace the real Provider executor check below.

## 4. Install the candidate on the second machine

Unpack only the archive for the second machine's operating system and architecture. Put the dynamic library in the matching CLIProxyAPI plugin directory, for example:

```text
plugins/linux/amd64/codex-token-usage.so
plugins/windows/amd64/codex-token-usage.dll
plugins/darwin/arm64/codex-token-usage.dylib
```

Use a dedicated data directory and start with quota probes and account protection disabled:

```bash
export CPA_TOKEN_USAGE_DIR="${PWD}/candidate-data-${RUN_ID}"
```

```yaml
plugins:
  enabled: true
  configs:
    codex-token-usage:
      enabled: true
      priority: 120
      quota_trigger_enabled: false
      account_protection_enabled: false
```

Restart CLIProxyAPI and confirm that it loads the candidate library, registers the plugin once, serves its management resources, and shuts down cleanly without a panic or leaked test controls.

## 5. Independent acceptance matrix

Record the command, observed result, CPA tag and commit, OS/architecture, candidate run URL, `HEAD_SHA`, and `BUNDLE_DIGEST` for every item.

1. **Integrity:** the top level contains exactly the ten manifest assets plus `checksums.txt`, every entry is a regular non-symlink file, all ten checksums pass `sha256sum --check --strict`, and the computed manifest digest equals the workflow summary.
2. **Latest CPA compatibility:** `CPA_COMPAT_CHANNEL=latest-release` passes and reports the latest published CPA tag/commit plus ABI/schema `1/1`.
3. **Native candidate load:** the downloaded library, not a local rebuild, starts, reconfigures, exposes management resources, and shuts down under that CPA release.
4. **Real CPA executor lifecycle with a local mock upstream:** enable account protection with a limit of one and issue the request through CPA's real Provider network executor, but route it only to a controlled local mock server. Do not use a real Provider credential, real account pool, external Provider endpoint, or production CPA service. Prove that a reservation exists while the mock request is in flight and returns to the baseline after CPA emits the terminal usage callback. Direct usage RPC injection is not acceptable evidence for this item.
5. **Fail-closed scheduling:** while the controlled first request holds the only reservation, a second request is rejected as saturated and is not dispatched upstream. A database busy/unavailable condition returns `scheduler_unavailable` rather than bypassing protection.
6. **Usage semantics:** verify one normal generation and one known non-generation callback. The normal request contributes to generation totals; `Generate=false` remains auditable but does not change generation token/cost totals, while both terminal callbacks attempt the matching reservation release.
7. **Upgrade safety:** back up a representative pre-v6 SQLite database with a SQLite-safe method, start the candidate, verify atomic migration and Provider-scoped state, and confirm the documented rollback procedure on a disposable copy.
8. **Operator surface:** verify the dashboard, summary JSON, exports, and diagnostics contain no credentials, auth paths, raw SQL errors, or raw xAI metadata.

Reject the candidate if any item fails or if evidence was collected from a different commit, run, or bundle digest. Do not authorize a rebuilt replacement under the old triple.

## 6. Promote the exact SHA, authorize, and publish the same artifact

After the signed second-machine report passes, promote the tested commit to `main` with a fast-forward update that preserves `HEAD_SHA` exactly. Do not use a merge commit, squash merge, or GitHub rebase merge because each changes the published source identity.

```bash
git fetch --no-tags origin \
  "+refs/heads/main:refs/remotes/origin/main" \
  "+refs/heads/${CANDIDATE_BRANCH}:refs/remotes/origin/${CANDIDATE_BRANCH}"
test "$(git rev-parse "origin/${CANDIDATE_BRANCH}")" = "${HEAD_SHA}"
test "$(git merge-base "origin/main" "${HEAD_SHA}")" = "$(git rev-parse origin/main)"
git push origin "${HEAD_SHA}:refs/heads/main"
test "$(git ls-remote origin refs/heads/main | awk '{print $1}')" = "${HEAD_SHA}"
```

If branch protection requires a privileged promotion path, the authorized maintainer must perform an equivalent non-force fast-forward to the same object ID. If `main` advanced or the server would create a different commit, reject this promotion, update the candidate branch, and repeat independent acceptance with a new run and digest.

After exact-SHA promotion, construct the authorization token:

```bash
AUTHORIZATION="${TAG}@${HEAD_SHA}@${BUNDLE_DIGEST}"
printf '%s\n' "${AUTHORIZATION}"
```

Set `CPA_INDEPENDENT_ACCEPTED_RELEASES` in the `independent-release` Environment to that exact token, or add it as a separate whitespace/comma-delimited entry. Then approve the waiting Environment deployment for the same `RUN_ID`. Approving before exact-SHA promotion makes the publish job fail closed.

The publish job will:

1. download the already uploaded `cpa-plugin-release-<version>` artifact from that run;
2. recheck the exact 11-file allowlist, `checksums.txt`, its bundle digest, and `origin/main == HEAD_SHA`;
3. verify the exact acceptance triple and revalidate that the CPA lock still names the latest published release;
4. refuse any unrelated tag or Release, while allowing only an annotated tag/draft created by this same run with the exact commit and bundle digest;
5. attest the downloaded files;
6. create or resume the annotated version tag whose message records the source commit, bundle digest, and workflow run;
7. stage and verify the exact assets in a draft, then publish without invoking a build step.

After publication, verify that the annotated tag resolves to `HEAD_SHA`, the Release contains exactly the expected assets, and the published `checksums.txt` still has `BUNDLE_DIGEST`. Remove obsolete authorization entries after the release is complete.

If publication fails after the accepted tag or draft is created, rerun the failed publish job in the same `RUN_ID`; exact tag-message, commit, digest, and asset checks make that recovery idempotent. If a draft contains unexpected assets, delete only that draft and rerun while retaining the accepted annotated tag. A published Release is accepted as an idempotent success only when every downloaded asset is byte-for-byte identical to the candidate.

If acceptance is rejected, leave the Environment unapproved and cancel the run. Fix the source, choose the appropriate next version, and repeat the complete procedure. Never create, move, or force-update a version tag to rescue a rejected candidate.

## Emergency repository-owner waiver

Use this only when the repository owner explicitly accepts publication without second-machine evidence. It does not disable automated source-security, CPA compatibility, race, vulnerability, multi-process, platform-build, asset, checksum, SBOM, attestation, exact-SHA, or tag-integrity gates.

Before dispatch, fast-forward `main` to the exact candidate commit and verify that the candidate branch still points to the same object. Then dispatch from that candidate branch with both waiver inputs:

```bash
VERSION=0.1.39
CANDIDATE_BRANCH=agent/v0.1.39-cpa-compat-hardening
git fetch origin main "${CANDIDATE_BRANCH}"
CANDIDATE_SHA="$(git rev-parse "origin/${CANDIDATE_BRANCH}")"
MAIN_SHA="$(git rev-parse origin/main)"
test "$(git merge-base "${MAIN_SHA}" "${CANDIDATE_SHA}")" = "${MAIN_SHA}"
git push origin "${CANDIDATE_SHA}:refs/heads/main"
test "$(git ls-remote origin refs/heads/main | awk '{print $1}')" = "${CANDIDATE_SHA}"

gh workflow run release.yml \
  --ref "${CANDIDATE_BRANCH}" \
  -f version="${VERSION}" \
  -f waive_independent_acceptance=true \
  -f waiver_confirmation="WAIVE_SECOND_MACHINE_v${VERSION}"
```

The waiver fails closed unless the triggering actor is the repository owner, the candidate SHA already equals `origin/main`, and the confirmation matches the exact version. The publish job uses the separate `owner-waived-release` Environment, writes the waiver into the job summary and annotated tag message, and requires the final GitHub Release body to display the waiver notice. Do not populate `CPA_INDEPENDENT_ACCEPTED_RELEASES` for this path.
