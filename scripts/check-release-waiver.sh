#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 <vX.Y.Z> <actor> <repository-owner> <confirmation>" >&2
  exit 2
fi

tag="$1"
actor="$2"
repository_owner="$3"
confirmation="$4"

if [[ ! "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Owner waiver requires a stable vX.Y.Z tag" >&2
  exit 1
fi
if [[ -z "${actor}" || "${actor}" != "${repository_owner}" ]]; then
  echo "Only the repository owner may waive independent second-machine acceptance" >&2
  exit 1
fi

expected="WAIVE_SECOND_MACHINE_${tag}"
if [[ "${confirmation}" != "${expected}" ]]; then
  echo "Owner waiver confirmation must exactly equal ${expected}" >&2
  exit 1
fi

echo "Repository-owner second-machine waiver authorized for ${tag}"
