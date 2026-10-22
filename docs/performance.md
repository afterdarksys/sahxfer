# Single-file performance

Measurements and implementation notes, 2026-10-22. These are local results,
not a claim to outperform every transport or an independent security audit.
One grant still transfers one regular file. The v1 wire layout is unchanged.

## Implemented

- Actionable overdue timers run immediately, including the QUIC datagram
  runner. Inactive feedback and cleared NACKs cannot create a busy loop.
- pace-bbr tolerates up to 2 ms of scheduling lateness. The previous 1 ms
  cutoff discarded credit on roughly 1 ms Linux timer wakeups plus overhead.
  Longer idle gaps reset credit; catch-up remains bounded by pacing and the
  flight window. QUIC still disables this controller.
- The flight window accounts for observed delivery-feedback spacing over
  ten samples, capped at 50 ms. This allowance expires, ignores replayed
  delivery counts, and never bypasses the loss cap or PROBE_RTT.
- New source data uses 256 KiB read-ahead. Pending frames own their bytes;
  repairs reread the file and receive fresh sequence numbers. The original
  source hash validation is retained.
- In-order DATA is hashed from authenticated plaintext only after a full
  successful write. Overlaps retain first-write-wins. Out-of-order bytes and
  ZERO ranges still fold from the temp file when contiguous.
- Decryption scratch space is reused and cleared on peer close. Failed opens
  expose no plaintext to the writer. Cipher and route-token comparison rules
  are unchanged.
- The common one-hole prefix update and missing-range visitor avoid repeated
  interval allocations. Short reads and writes fail closed.
- `--diag` reports sender pacing state, bandwidth estimate, flight bytes,
  window cap, delivered prefix, and RTT at most once per second. No credentials,
  grant material, or file contents enter these diagnostics.

## Reproduce

```sh
go test ./...
go test -race ./...
go vet ./...
go test ./internal/engine -run '^$' -bench BenchmarkFile -benchmem -count=3
go test ./internal/udp -run '^$' -bench BenchmarkDiskTransfer -benchtime=1x -count=3
go test ./internal/udp -run '^TestLoopbackThroughput30MB$' -count=3 -v
```

Run benchmarks without concurrent compiles or other load. Record OS, CPU,
Go version, granted socket buffers, filesystem, and whether caches are warm.
Do not compare a memory-file loopback result with a disk-transfer result.

The file microbenchmarks use 4 MiB of nonzero data on actual files. They
isolate source classification and receiver writes/hashing, excluding network,
AEAD, preparation, and durable commit. On Darwin amd64, Intel i9-9880H,
Go 1.27, three samples before and after the I/O changes:

| Measurement | Before | After |
| --- | --- | --- |
| Source classification | 814–845 MB/s | 3,273–3,369 MB/s |
| Receiver writes and hash | 190–214 MB/s | 273–282 MB/s |
| Receiver allocations per 4 MiB | 3,651 | 9 |

The baseline is commit `56d69c7` with the same benchmark code. These are
warm-cache results. Source buffering adds bounded memory and does not yet
remove the allocation of each outgoing plaintext and ciphertext frame.

`BenchmarkDiskTransfer` moves 30 MB through actual source and destination
files over loopback UDP. Timing includes both source hash passes, encryption,
transfer, destination fsync, and rename. Source creation and independent
byte-for-byte destination verification are outside the timer. It does not
contact SystemAPI or measure a cold disk. The original-code baseline measured
24.3–40.6 MB/s; the first optimized runs measured 43.9–54.9 MB/s. Host load
varied, so these ranges are evidence of improvement, not a precise speedup.
After the final pacing changes and completion of the test suites, three
additional runs measured 55.0, 55.2, and 55.2 MB/s (0.543–0.545 s each).

Linux container loopback with memory-backed files timed out at 16 s in three
consecutive runs before correcting pacing slack. Diagnostics showed bandwidth
near 2 MB/s and flight bytes below the window cap. After the 2 ms correction,
three runs completed in 0.271–0.384 s, or 78–111 MB/s. That test excludes source
preparation and durable file commit; it is a scheduling regression check.

## Remaining work

1. Measure sustained transfers between physical Linux hosts at multiple RTTs,
   with random loss, burst loss, reordering, reverse-path outages, competing
   flows, and slow storage. Existing deterministic path tests remain required.
2. Separate selectively delivered byte credit from contiguous completion.
   Today a missing prefix still keeps later segments in flight. ZERO and
   retransmission accounting need a specified, tested design before changing it.
3. Consolidate duplicated source validation without weakening change detection
   or allowing preparation to consume the grant's first-packet deadline.
4. Reduce outgoing allocations and improve effective send batches. Any buffer
   pool needs explicit ownership until socket completion and failure tests.
5. Evaluate batched destination writes, kernel pacing, and a real Linux
   io_uring backend using profiles. No io_uring implementation is claimed here.

Retain TLS 1.3, ChaCha20-Poly1305, authenticated grants, path confinement,
first-write-wins, hash verification, and durable commit throughout. Compression,
MTU negotiation, resume, and wire-format changes require separate specifications.

## Validation

The final implementation passed `go test ./...` on Darwin amd64 (Go 1.27.3)
and in the local Linux `golang:1.27` container, plus `go test -race ./...`
and `go vet ./...` on Darwin. The existing suites cover tampered packets,
expiry, grant binding and purpose, path escape and symlinks, hash mismatch,
replay, and peer pinning. Added tests cover overdue and inactive timers,
repair recheck timing, first-send credit, 1.1 ms scheduling lateness, bounded
and aging feedback allowance, overlapping writes, short I/O, source-buffer
ownership, scratch clearing, and a bitmap reference check of hole tracking.

These checks do not establish Internet fairness, production host isolation,
or performance at 10/25/100 Gbit/s. Those remain deployment and evaluation work.
