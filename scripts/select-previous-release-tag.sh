#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/semver.sh
source "${script_dir}/semver.sh"

current_tag="${1:?usage: select-previous-release-tag.sh CURRENT_TAG CURRENT_IS_PRERELEASE}"
current_prerelease="${2:?usage: select-previous-release-tag.sh CURRENT_TAG CURRENT_IS_PRERELEASE}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required to select the previous published release" >&2
  exit 2
fi
case "${current_prerelease}" in
  true | false) ;;
  *)
    echo "CURRENT_IS_PRERELEASE must be true or false; got ${current_prerelease}" >&2
    exit 2
    ;;
esac

releases_json="$(cat)"
if ! jq -e 'type == "array" and all(.[]; type == "object")' <<< "${releases_json}" >/dev/null; then
  echo "GitHub releases response must be a JSON array of objects" >&2
  exit 1
fi

if [[ "${current_prerelease}" == "false" ]]; then
  current_version="${current_tag#v}"
  if [[ "${current_tag}" != v* ]] || ! is_stable_semver "${current_version}"; then
    echo "Stable publication requires a plain semantic version tag; got ${current_tag}" >&2
    exit 1
  fi
  highest_stable_version=""
  while IFS= read -r published_tag; do
    [[ -z "${published_tag}" || "${published_tag}" == "${current_tag}" ]] && continue
    published_version="${published_tag#v}"
    if [[ "${published_tag}" != v* ]] || ! is_stable_semver "${published_version}"; then
      echo "Published stable Release has a non-SemVer tag: ${published_tag}" >&2
      exit 1
    fi
    if [[ -z "${highest_stable_version}" ]] || semver_stable_gt "${published_version}" "${highest_stable_version}"; then
      highest_stable_version="${published_version}"
    fi
  done < <(
    jq -r '
      .[]
      | select((.draft // false) == false)
      | select((.prerelease // false) == false)
      | select(.published_at != null)
      | .tag_name // ""' <<< "${releases_json}"
  )
  if [[ -n "${highest_stable_version}" ]] && ! semver_stable_gt "${current_version}" "${highest_stable_version}"; then
    echo "Stable publication ${current_tag} must be newer than the highest published stable version v${highest_stable_version}" >&2
    exit 1
  fi
fi

jq -r \
  --arg current "${current_tag}" \
  --argjson include_prereleases "${current_prerelease}" \
  '[
    .[]
    | select((.draft // false) == false)
    | select(.published_at != null)
    | select((.tag_name // "") != $current)
    | select($include_prereleases or ((.prerelease // false) == false))
  ]
  | sort_by([.published_at, (.id // 0), (.tag_name // "")])
  | last
  | .tag_name // ""' <<< "${releases_json}"
