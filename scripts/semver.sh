#!/usr/bin/env bash

is_semver() {
  local version="${1:-}"
  local core prerelease identifier
  [[ "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] || return 1
  prerelease="${BASH_REMATCH[5]:-}"
  [[ -z "${prerelease}" ]] && return 0
  IFS='.' read -r -a identifiers <<< "${prerelease}"
  for identifier in "${identifiers[@]}"; do
    if [[ "${identifier}" =~ ^[0-9]+$ && "${identifier}" != "0" && "${identifier}" == 0* ]]; then
      return 1
    fi
  done
}
