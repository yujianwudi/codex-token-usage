#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
gate="${script_dir}/check-release-acceptance.sh"
accepted_commit="0123456789abcdef0123456789abcdef01234567"
other_commit="89abcdef0123456789abcdef0123456789abcdef"
accepted_digest="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
other_digest="89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"

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
