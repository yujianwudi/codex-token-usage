#!/usr/bin/env bash

is_semver() {
  local version="${1:-}"
  local prerelease identifier
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

is_stable_semver() {
  local version="${1:-}"
  is_semver "${version}" && [[ "${version}" != *[-+]* ]]
}

# semver_stable_gt reports whether the first plain MAJOR.MINOR.PATCH version is
# strictly newer than the second. Component lengths are compared before their
# lexical values so arbitrarily large valid SemVer numbers do not overflow
# Bash's fixed-width arithmetic.
semver_stable_gt() {
  local candidate="${1:-}" baseline="${2:-}" LC_ALL=C
  local -a candidate_parts baseline_parts
  local i candidate_part baseline_part
  is_stable_semver "${candidate}" || return 1
  is_stable_semver "${baseline}" || return 1
  IFS='.' read -r -a candidate_parts <<< "${candidate}"
  IFS='.' read -r -a baseline_parts <<< "${baseline}"
  for i in 0 1 2; do
    candidate_part="${candidate_parts[i]}"
    baseline_part="${baseline_parts[i]}"
    if (( ${#candidate_part} > ${#baseline_part} )); then
      return 0
    fi
    if (( ${#candidate_part} < ${#baseline_part} )); then
      return 1
    fi
    if [[ "${candidate_part}" > "${baseline_part}" ]]; then
      return 0
    fi
    if [[ "${candidate_part}" < "${baseline_part}" ]]; then
      return 1
    fi
  done
  return 1
}
