#!/usr/bin/env bash
set -euo pipefail

results="${1:?usage: check-benchmark-budget.sh BENCHMARK_RESULTS}"
if [[ ! -f "${results}" ]]; then
  echo "Benchmark results do not exist: ${results}" >&2
  exit 1
fi

minimum_samples="${BENCHMARK_MIN_SAMPLES:-3}"
if [[ ! "${minimum_samples}" =~ ^[1-9][0-9]*$ ]]; then
  echo "BENCHMARK_MIN_SAMPLES must be a positive integer" >&2
  exit 1
fi

# These ceilings are intentionally well above the audited steady-state values
# but far below the scheduler's 750 ms deadline. They catch structural hot-path
# regressions while leaving ample headroom for noisy shared GitHub runners.
declare -A max_ns=(
  [BenchmarkSchedulerPrivacyQuarantineEmpty100Accounts]=1000
  [BenchmarkSchedulerHealthyFastPath100Accounts]=1000000
  [BenchmarkSchedulerHealthyPersistentRevision100Accounts]=5000000
  [BenchmarkSchedulerRestrictedSnapshot100Accounts]=10000000
  [BenchmarkSchedulerMixedFiltering100Accounts]=10000000
  [BenchmarkSchedulerProviderQuarantineFiltering100Accounts]=5000000
  [BenchmarkProtectedPick100Accounts50kEvents]=20000000
  [BenchmarkIsMixedSchedulerRequestSingleProvider]=1000
)
declare -A max_bytes=(
  [BenchmarkSchedulerPrivacyQuarantineEmpty100Accounts]=0
  [BenchmarkSchedulerHealthyFastPath100Accounts]=65536
  [BenchmarkSchedulerHealthyPersistentRevision100Accounts]=65536
  [BenchmarkSchedulerRestrictedSnapshot100Accounts]=524288
  [BenchmarkSchedulerMixedFiltering100Accounts]=1048576
  [BenchmarkSchedulerProviderQuarantineFiltering100Accounts]=262144
  [BenchmarkProtectedPick100Accounts50kEvents]=1048576
  [BenchmarkIsMixedSchedulerRequestSingleProvider]=0
)
declare -A max_allocs=(
  [BenchmarkSchedulerPrivacyQuarantineEmpty100Accounts]=0
  [BenchmarkSchedulerHealthyFastPath100Accounts]=100
  [BenchmarkSchedulerHealthyPersistentRevision100Accounts]=500
  [BenchmarkSchedulerRestrictedSnapshot100Accounts]=3000
  [BenchmarkSchedulerMixedFiltering100Accounts]=4000
  [BenchmarkSchedulerProviderQuarantineFiltering100Accounts]=1000
  [BenchmarkProtectedPick100Accounts50kEvents]=4000
  [BenchmarkIsMixedSchedulerRequestSingleProvider]=0
)
declare -A seen=()

failed=0
while read -r raw_name ns_per_op bytes_per_op allocs_per_op; do
  name="${raw_name}"
  if [[ "${name}" =~ ^(.+)-[0-9]+$ ]]; then
    name="${BASH_REMATCH[1]}"
  fi
  if [[ -z "${max_ns[${name}]+x}" ]]; then
    continue
  fi
  seen["${name}"]=$(( ${seen["${name}"]:-0} + 1 ))

  if ! awk -v actual="${ns_per_op}" -v limit="${max_ns[${name}]}" 'BEGIN { exit !(actual <= limit) }'; then
    echo "${name}: ${ns_per_op} ns/op exceeds ${max_ns[${name}]} ns/op" >&2
    failed=1
  fi
  if ! awk -v actual="${bytes_per_op}" -v limit="${max_bytes[${name}]}" 'BEGIN { exit !(actual <= limit) }'; then
    echo "${name}: ${bytes_per_op} B/op exceeds ${max_bytes[${name}]} B/op" >&2
    failed=1
  fi
  if ! awk -v actual="${allocs_per_op}" -v limit="${max_allocs[${name}]}" 'BEGIN { exit !(actual <= limit) }'; then
    echo "${name}: ${allocs_per_op} allocs/op exceeds ${max_allocs[${name}]} allocs/op" >&2
    failed=1
  fi
done < <(
  awk '$1 ~ /^Benchmark/ && $4 == "ns/op" && $6 == "B/op" && $8 == "allocs/op" { print $1, $3, $5, $7 }' "${results}"
)

for name in "${!max_ns[@]}"; do
  samples="${seen[${name}]:-0}"
  if (( samples < minimum_samples )); then
    echo "${name}: found ${samples} samples, want at least ${minimum_samples}" >&2
    failed=1
  fi
done

if (( failed != 0 )); then
  exit 1
fi

echo "Scheduler benchmark budgets passed (${minimum_samples}+ samples per benchmark)."
