#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

expect_selection() {
  local description="$1"
  local expected="$2"
  local current_tag="$3"
  local current_prerelease="$4"
  local releases_json="$5"
  local actual
  actual="$(
    printf '%s\n' "${releases_json}" |
      bash scripts/select-previous-release-tag.sh "${current_tag}" "${current_prerelease}"
  )"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "${description}: selected ${actual:-<empty>}, want ${expected:-<empty>}" >&2
    exit 1
  fi
}

expect_rejection() {
  local description="$1"
  local current_tag="$2"
  local releases_json="$3"
  if printf '%s\n' "${releases_json}" |
    bash scripts/select-previous-release-tag.sh "${current_tag}" false >/dev/null 2>&1; then
    echo "${description}: invalid stable publication order was accepted" >&2
    exit 1
  fi
}

stable_releases='[
  {"tag_name":"v0.1.33","id":33,"draft":false,"prerelease":false,"published_at":"2026-07-15T07:45:06Z"},
  {"tag_name":"v0.1.34","id":34,"draft":false,"prerelease":false,"published_at":"2026-07-15T12:37:01Z"}
]'
expect_selection \
  "unpublished intervening tag" \
  "v0.1.34" \
  "v0.1.36" \
  false \
  "${stable_releases}"

mixed_releases='[
  {"tag_name":"v0.1.36","draft":false,"prerelease":false,"published_at":"2026-07-15T17:07:39Z"},
  {"tag_name":"v0.1.35","draft":true,"prerelease":false,"published_at":null},
  {"tag_name":"v0.1.37-rc.1","draft":false,"prerelease":true,"published_at":"2026-07-16T02:00:00Z"},
  {"tag_name":"v0.1.37","draft":false,"prerelease":false,"published_at":"2026-07-16T03:00:00Z"}
]'
expect_selection \
  "stable release ignores current and prerelease entries" \
  "v0.1.36" \
  "v0.1.37" \
  false \
  "${mixed_releases}"
expect_selection \
  "prerelease uses latest published release" \
  "v0.1.37" \
  "v0.1.38-rc.1" \
  true \
  "${mixed_releases}"

same_timestamp_releases='[
  {"tag_name":"v0.1.41","id":41,"draft":false,"prerelease":false,"published_at":"2026-07-16T04:00:00Z"},
  {"tag_name":"v0.1.40","id":40,"draft":false,"prerelease":false,"published_at":"2026-07-16T04:00:00Z"}
]'
expect_selection \
  "same published_at uses release id tie-break" \
  "v0.1.41" \
  "v0.1.42" \
  false \
  "${same_timestamp_releases}"

same_timestamp_and_id_releases='[
  {"tag_name":"v0.1.42","id":42,"draft":false,"prerelease":false,"published_at":"2026-07-16T05:00:00Z"},
  {"tag_name":"v0.1.43","id":42,"draft":false,"prerelease":false,"published_at":"2026-07-16T05:00:00Z"}
]'
expect_selection \
  "same published_at and id uses tag tie-break" \
  "v0.1.43" \
  "v0.1.44" \
  false \
  "${same_timestamp_and_id_releases}"
expect_selection "first published release" "" "v0.1.0" false '[]'

expect_rejection \
  "lower version published after a higher stable version" \
  "v0.1.40" \
  '[
    {"tag_name":"v0.1.41","id":41,"draft":false,"prerelease":false,"published_at":"2026-07-16T03:00:00Z"},
    {"tag_name":"v0.1.39","id":39,"draft":false,"prerelease":false,"published_at":"2026-07-16T04:00:00Z"}
  ]'
expect_rejection \
  "published stable release with ambiguous non-SemVer tag" \
  "v0.1.40" \
  '[{"tag_name":"stable","draft":false,"prerelease":false,"published_at":"2026-07-16T04:00:00Z"}]'

echo "Previous published release selection tests passed"
