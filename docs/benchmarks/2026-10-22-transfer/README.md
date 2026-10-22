# Local transfer evidence, 2026-10-22

Baseline revision: `57bac709bc9523ba2bb61ddf51341df8c37efdd5`, with the benchmark
instrumentation accompanying these reports. Darwin 24.6.0 amd64, Intel i9-9880H,
Go 1.27.3. APFS temporary files; warm-cache setup, random contents, loopback UDP.
Both sockets granted 8 MiB send and receive buffers. No concurrent benchmark,
test, or compile jobs from this session ran during timing samples.

`timing.txt`: 256 MiB, three unprofiled samples per payload/pipeline case.
`2gib-timing.txt`: 2 GiB, one unprofiled sample per payload profile, pipeline off.
`network-cpu-top.txt`: separate profile run aggregating all four 256 MiB cases,
filtered to runner/commit CPU labels. Percentages retain the whole-profile
sample denominator; syscall stack samples are not a wall-time breakdown.
`alloc-top.txt`: separate sampled allocation report, whole process, cumulative
bytes rather than peak RSS. Do not compare profiled timing with unprofiled runs.

Full binary, profiles, trace, metadata, and benchmark patch were saved locally
in `/tmp/sahxfer-perf-20261022-tranches`; those temporary artifacts are not a
portable archive and may be removed by the OS. Reproduction instructions and
measurement boundaries are in ../../performance-lab.md.

Validation: full Darwin Go suite, go vet, both legacy benchmark variants under
the race detector, the four sustained variants, and independent size/hash
verification after every measured commit. No physical Linux or competitor run
is represented by these files.
