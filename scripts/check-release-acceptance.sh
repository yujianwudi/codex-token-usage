#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/semver.sh
source "${script_dir}/semver.sh"

tag="${1:-}"
commit="${2:-}"
bundle_digest="${3:-}"
if [[ "${tag}" != v* ]] || ! is_semver "${tag#v}"; then
	echo "Independent acceptance check requires an exact v-prefixed SemVer tag" >&2
	exit 1
fi
if [[ "${tag#v}" == *[-+]* ]]; then
	echo "Independent acceptance check accepts stable MAJOR.MINOR.PATCH versions only" >&2
	exit 1
fi
if [[ ! "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
	echo "Independent acceptance check requires the exact 40-character release commit" >&2
	exit 1
fi
if [[ ! "${bundle_digest}" =~ ^[0-9a-f]{64}$ ]]; then
	echo "Independent acceptance check requires the exact lowercase SHA-256 candidate bundle digest" >&2
	exit 1
fi

# This repository variable is intentionally a non-secret, whitespace- or
# comma-separated allowlist of tag@commit@bundle-digest triples. It must be
# scoped to the independent-release Environment and updated by the
# repository owner only after the independent second-machine report approves
# that exact source commit and verified candidate bundle. Binding the digest
# prevents a later workflow run from rebuilding different assets under an
# already accepted version and commit.
accepted="${CPA_INDEPENDENT_ACCEPTED_RELEASES:-}"
accepted="$(tr ',\r\n\t' '    ' <<<"${accepted}")"
read -r -a accepted_releases <<<"${accepted}"
expected="${tag}@${commit}@${bundle_digest}"
for candidate in "${accepted_releases[@]}"; do
	if [[ "${candidate}" == "${expected}" ]]; then
		echo "Independent acceptance authorization verified for ${expected}"
		exit 0
	fi
done

echo "Release ${expected} is not authorized by independent second-machine acceptance" >&2
echo "After acceptance, add the exact tag@commit@bundle-digest triple to the independent-release Environment variable CPA_INDEPENDENT_ACCEPTED_RELEASES" >&2
exit 1
