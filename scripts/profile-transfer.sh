#!/usr/bin/env bash
# Local loopback evidence only. No grants, credentials, or packet captures.
set -euo pipefail
umask 077
if [[ $# != 1 ]]; then
  echo "usage: $0 NEW_OUTPUT_DIRECTORY" >&2
  exit 2
fi
mkdir -- "$1"
out=$(cd -- "$1" && pwd)
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "$repo"
bench=${SAHXFER_BENCH_PATTERN:-'^BenchmarkDiskTransfer/pipeline=false$'}
count=${SAHXFER_BENCH_COUNT:-3}
if [[ ! $count =~ ^[1-9][0-9]*$ ]]; then
  echo 'SAHXFER_BENCH_COUNT must be a positive integer' >&2
  exit 2
fi
{
  date -u
  uname -a
  go version
  git rev-parse HEAD
  git status --short
  printf 'benchmark=%s\ncount=%s\nbytes=%s\ntransfer_timeout=%s\nTMPDIR=%s\n' \
    "$bench" "$count" "${SAHXFER_BENCH_BYTES:-default}" \
    "${SAHXFER_BENCH_TIMEOUT:-default}" "${TMPDIR:-/tmp}"
  df -h "${TMPDIR:-/tmp}"
} > "$out/environment.txt"
git diff -- internal/udp/disk_test.go > "$out/benchmark.patch"
go test -c -o "$out/udp.test" ./internal/udp
# Timing samples are separate from profiling runs. Profiles include untimed
# fixture creation/verification: the Go benchmark timer does not gate profilers.
"$out/udp.test" -test.run '^$' -test.bench "$bench" -test.benchtime 1x \
  -test.count "$count" -test.timeout 1h -test.benchmem -test.v | tee "$out/timing.txt"
"$out/udp.test" -test.run '^$' -test.bench "$bench" -test.benchtime 1x \
  -test.timeout 1h -test.cpuprofile "$out/cpu.pprof" \
  -test.memprofile "$out/heap.pprof" > "$out/profile-run.txt"
"$out/udp.test" -test.run '^$' -test.bench "$bench" -test.benchtime 1x \
  -test.timeout 1h -test.trace "$out/trace.out" > "$out/trace-run.txt"
go tool pprof -top "$out/udp.test" "$out/cpu.pprof" > "$out/cpu-top.txt"
go tool pprof -top -tagfocus=phase=network-and-commit "$out/udp.test" "$out/cpu.pprof" > "$out/network-cpu-top.txt"
go tool pprof -top -alloc_space "$out/udp.test" "$out/heap.pprof" > "$out/alloc-top.txt"
printf 'Results: %s\n' "$out"
