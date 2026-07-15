#!/usr/bin/env bash
set -euo pipefail

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

jq -r \
  --arg current "${current_tag}" \
  --argjson include_prereleases "${current_prerelease}" \
  '[
    .[]
    | select((.draft // false) == false)
    | select(.published_at != null)
    | select((.tag_name // "") != $current)
    | select($include_prereleases or ((.prerelease // false) == false))
  ][0].tag_name // ""' <<< "${releases_json}"
