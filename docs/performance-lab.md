# Transfer measurement lab

The measurement tranches add phase timings, bounded large-file fixtures, and
repeatable local profiling. They change no production engine, grant, cipher,
congestion controller, or wire behavior. Physical-host testing remains a
separate experiment; loopback cannot establish WAN throughput or fairness.

## Phase timings

Both `BenchmarkDiskTransfer` (30 MB) and `BenchmarkSustainedTransfer` report:

| Metric | Boundary |
| --- | --- |
| `prepare-ns/op` | Source open and initial SHA-256, before engine creation |
| `attach-ns/op` | `AttachSource`, including its mandatory validation hash |
| `setup-ns/op` | Engine, destination, socket, and context setup |
| `transfer-ns/op` | Runner launch through entry to the receiver commit hook |
| `commit-ns/op` | Actual temp-file commit, including fsync and rename |
| `close-ns/op` | Commit return through both runners returning |
| `transfer-MB/s` | File bytes divided by the transfer interval, decimal MB/s |
| Go's `MB/s` | File bytes divided by the complete benchmark timed interval |

Transfer time includes startup, pacing, repairs, receiver writes, and final
hash verification. Streaming hash work overlaps packet processing; these
metrics do not isolate its CPU cost. Close time includes the DONE/CLOSE_ACK
exchange. Go's timer additionally includes deferred resource cleanup and small
measurement overhead, so its total is slightly larger than the phase sum.
There is no claim that transfer-MB/s is steady-state wire throughput or a
measurement of time to first byte.

Source creation and independent destination size/SHA-256 verification remain
outside the benchmark timer. The fixture is now random data streamed from
`crypto/rand`, replacing the former deterministic, file-sized memory buffer.
Verification also streams with bounded memory. This changes the fixture, so
historical numbers are context rather than a strictly matched baseline.
These are warm-cache runs unless a separate experiment establishes otherwise.

The benchmark logs granted socket buffers for both peers. No packet contents,
keys, route tokens, or grant files are recorded.

## Sustained local matrix

Large tests are opt-in and cover `internet`/`dc` and source pipeline off/on:

```sh
SAHXFER_BENCH_BYTES=2147483648 SAHXFER_BENCH_TIMEOUT=10m \
  go test ./internal/udp -run '^$' -bench '^BenchmarkSustainedTransfer$' \
  -benchtime=1x -count=3 -timeout=1h -benchmem -v
```

Reserve room for source, destination, and the replacement temp file (up to
three file sizes when an iteration replaces the previous target). `TMPDIR`
selects the fixture filesystem. Run one benchmark process at a time, without
compiles or tests competing for CPU. Byte counts must be positive signed
64-bit integers. The per-transfer timeout begins after preparation; Go's
outer timeout covers the entire matrix. With no byte-count environment
variable, the sustained benchmark skips even under `-bench .`.

The local DC case uses larger datagrams on loopback. It does not authorize DC
on an Internet deployment; real grants still require tenant-network policy.

## Profile artifacts

```sh
scripts/profile-transfer.sh /tmp/sahxfer-profile-new

SAHXFER_BENCH_BYTES=268435456 \
SAHXFER_BENCH_PATTERN='^BenchmarkSustainedTransfer/profile=internet/pipeline=false$' \
  scripts/profile-transfer.sh /tmp/sahxfer-sustained-new
```

The output directory must not already exist. The runner compiles once, then
runs three unprofiled timing samples (`SAHXFER_BENCH_COUNT` overrides this),
a CPU/allocation profile run, and a separate execution-trace run. It retains
the binary, environment metadata, benchmark patch, raw outputs, profiles,
trace, and top reports. Profiled timing is not used as throughput evidence.

The benchmark timer does not control Go's profilers: full profiles also contain
fixture creation and independent verification. Both runners inherit the CPU
label `phase=network-and-commit`; `network-cpu-top.txt` filters on that label.
It includes commit and close but excludes initial hashing and fixture creation.
Allocation profiles are process-wide and are not filtered by CPU labels.
Use `go tool trace /tmp/sahxfer-profile-new/trace.out` for scheduling analysis.
Profiles describe on-CPU work; waiting for pacing, disk, or feedback requires
the trace and wall-clock timings as well.

## Physical Linux experiment, pending hosts

Record two host identities, kernel/Go versions, CPU models, filesystem/storage,
NIC link speeds, MTU, granted socket buffers, and cache policy. Use dedicated
test directories and the same revision on both machines. Build before timing.
Use the existing CLI bootstrap-grant flow and explicit operator-supplied 0600
grant paths, transferring that file only through authenticated SSH. Create a
fresh grant for each run after preparing the source. Do not capture grant
contents, packet headers containing route tokens, or credentials in artifacts.

Start with a multi-gigabyte random file and three clean-path samples for each
payload profile permitted by policy, pipeline off/on. Independently verify
size and SHA-256 at the destination. Record preparation, whole command time,
receiver completion, CPU time, peak RSS, disk traffic, and `--diag` output.
The benchmark's phase metrics currently exist only in the local harness;
the production CLI does not yet expose equivalent phase timing.

Then test controlled RTT, random and burst loss, reordering, reverse-path
outage, competing traffic, and slow storage one at a time. Apply impairment
only to an isolated test interface or namespace after identifying it; do not
modify the hosts' management interface. Record the exact impairment and its
cleanup, and compare against a clean-path control. Missing host information
blocks these measurements, not the local tooling.

Use the results to choose between outgoing allocation work, effective socket
batching, destination batching, and kernel pacing. None is assumed to be the
next bottleneck. Source-validation consolidation and selective delivery credit
still require their own security and accounting designs.
