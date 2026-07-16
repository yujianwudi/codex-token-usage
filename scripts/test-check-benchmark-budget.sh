#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
checker="scripts/check-benchmark-budget.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

good="${tmp_dir}/good.txt"
printf '%s\n' \
  'BenchmarkSchedulerPrivacyQuarantineEmpty100Accounts-2 1000 3.2 ns/op 0 B/op 0 allocs/op' \
  'BenchmarkSchedulerHealthyFastPath100Accounts-2 1000 6000 ns/op 8608 B/op 8 allocs/op' \
  'BenchmarkSchedulerHealthyPersistentRevision100Accounts-2 1000 25000 ns/op 10032 B/op 51 allocs/op' \
  'BenchmarkSchedulerRestrictedSnapshot100Accounts-2 1000 375000 ns/op 76616 B/op 1057 allocs/op' \
  'BenchmarkSchedulerMixedFiltering100Accounts-2 1000 600000 ns/op 130424 B/op 1536 allocs/op' \
  'BenchmarkSchedulerProviderQuarantineFiltering100Accounts-2 1000 135000 ns/op 45408 B/op 317 allocs/op' \
  'BenchmarkProtectedPick100Accounts50kEvents-2 1000 750000 ns/op 209920 B/op 1563 allocs/op' \
  'BenchmarkIsMixedSchedulerRequestSingleProvider-2 1000 16 ns/op 0 B/op 0 allocs/op' \
  > "${good}"
BENCHMARK_MIN_SAMPLES=1 bash "${checker}" "${good}" >/dev/null

slow="${tmp_dir}/slow.txt"
cp "${good}" "${slow}"
printf '%s\n' 'BenchmarkProtectedPick100Accounts50kEvents-2 1000 20000001 ns/op 209920 B/op 1563 allocs/op' >> "${slow}"
if BENCHMARK_MIN_SAMPLES=1 bash "${checker}" "${slow}" >/dev/null 2>&1; then
  echo "Benchmark budget accepted an over-budget scheduler result" >&2
  exit 1
fi

missing="${tmp_dir}/missing.txt"
printf '%s\n' 'BenchmarkSchedulerHealthyFastPath100Accounts-2 1000 6000 ns/op 8608 B/op 8 allocs/op' > "${missing}"
if BENCHMARK_MIN_SAMPLES=1 bash "${checker}" "${missing}" >/dev/null 2>&1; then
  echo "Benchmark budget accepted missing benchmark evidence" >&2
  exit 1
fi

echo "Benchmark budget checker tests passed."
