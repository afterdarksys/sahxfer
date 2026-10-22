# Experimental transport research

Date: 2026-10-22. Baseline: `1d061d2`. Status: research and proposed experiments,
not a change to the v1 contract or an implemented v2. No new dependencies.

Follow-up: the first implementation experiment now exists as opt-in
`put --pipeline-source`: one source read-ahead worker and two bounded buffers.
It overlaps reads with engine processing; it is not the full read/write/crypto
pipeline proposed below. See `docs/performance.md` for measured results and
`docs/design.md` section 7.3 for ownership and shutdown rules. The inventory
below records the baseline at `1d061d2`.

## Current implementation

| Area | What exists | What does not |
| --- | --- | --- |
| Chunking | MSS-sized DATA and negotiated ZERO runs | Rabin, FastCDC, content-addressed reuse, delta transfer |
| Integrity | Whole-file SHA-256, incremental hashing; ChaCha20-Poly1305 per datagram | BLAKE3, xxHash, authenticated chunk manifest or Merkle proofs |
| Network pipeline | Multiple packets in flight, paced window, NACK repairs, batched socket calls | A concurrent disk/crypto/write worker pipeline |
| File I/O | Synchronous positional reads/writes; 256 KiB source lookahead | An actual io_uring submission backend or Dispatch I/O backend |
| Darwin sockets | Up to 32 datagrams per recvmsg_x/sendmsg_x through RawConn | A shared submission/completion ring equivalent to io_uring |
| Queues | Engine-owned slices; channels in the QUIC runner | A custom lock-free processing ring |

Evidence: `internal/engine/engine.go` (AttachSource, sendData, readSource,
foldHash, noteContig); `internal/udp/udp.go`; `internal/udp/sockio_{linux,darwin}.go`;
`internal/quic/datagram.go`; `internal/cli/xfer.go` (hashFile).

Some existing design prose still describes Darwin as one datagram per syscall.
The current Darwin implementation already batches. Its syscall numbers and ABI
are explicitly identified in the source as outside the stable userland SDK API;
support across OS versions needs capability checks and a safe fallback.

## 1. Content-defined chunking

Rabin fingerprinting can select content-dependent boundaries. FastCDC uses a
Gear-based approach with minimum-size skipping and size normalization. Neither
boundary fingerprint is an integrity proof. See the original
[FastCDC paper](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia).

For sahxfer, the purpose would be to avoid sending chunks already available at
the destination, including repeated content within a transfer. It does not
intrinsically make a new, unique file cheaper to transmit. Chunk discovery,
manifest exchange, indexing, and candidate verification add CPU and I/O.

Proposed experiment: compare fixed-size chunks, Rabin, and FastCDC on successive
VM images, database snapshots, and uncompressed archives. Include inserted bytes
near the beginning, changed blocks, zero-heavy files, and compressed/encrypted
files. Compare equivalent observed chunk sizes, not just matching parameters.

FastCDC is a baseline, not an assumed winner. Research has advanced:

- [VectorCDC, FAST 2025](https://www.usenix.org/conference/fast25/presentation/udayashankar)
  explores SSE/AVX acceleration of hashless CDC. Its published results are not
  sahxfer measurements and do not establish Apple Silicon performance.
- [Benchmarking CDC, October 2026](https://arxiv.org/abs/2610.13704) separates
  boundary algorithms from normalization and other policies. It identifies
  misleading comparisons caused by mismatched realized chunk sizes. Treat its
  results as workload-specific evidence, not a universal algorithm ranking.

An experimental delta mode needs explicit authorization to read the basis file
or tenant-scoped chunk store. A write grant must not implicitly permit searching
arbitrary files or another tenant's cache. A digest match selects a candidate;
the destination must verify the candidate's cryptographic content hash before
reuse. Do not expose a global chunk-existence oracle.

Chunk lengths and reuse patterns can reveal information despite encryption.
[Breaking and Fixing Content-Defined Chunking](https://eprint.iacr.org/2025/558)
shows why adding an ad hoc secret seed to a chunker is not a complete mitigation.
The proposed protocol must define this leakage, rather than claiming the AEAD
hides it. Chunk manifests travel encrypted on the data plane, not as bulk
SystemAPI WebSocket traffic.

## 2. Hashing pipeline

xxHash/XXH3 is explicitly non-cryptographic. It is suitable for a speculative
lookup or duplicate-candidate filter, not the authenticated identity of a file
or reused chunk. A collision must never authorize skipping bytes. See the
[xxHash specification](https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md).

BLAKE3 is the stronger experimental file-hash candidate. Its tree supports SIMD
and parallel computation; actual multithreading depends on the implementation
and API. Calling a streaming hasher does not automatically use all cores.
The [official implementation](https://github.com/BLAKE3-team/BLAKE3) provides
test vectors and describes its supported acceleration paths.

Experiment with unkeyed 256-bit BLAKE3 for file identity while retaining
ChaCha20-Poly1305 for packets. Compare the actual Go implementation with stdlib
SHA-256 on amd64 and arm64, small packets versus large buffers, and one versus
multiple workers. Include full preparation-to-commit time, not just hash GB/s.
For example, [zeebo/blake3](https://github.com/zeebo/blake3) advertises x86 SIMD;
that alone is insufficient evidence of arm64 parity or multicore execution.

Do not change SHA-256 globally: route-token comparison and grant-material
binding have their own mandatory SHA-256 contracts. Changing file identity
requires an explicit algorithm identifier in the grant, lease binding, result,
and DONE semantics. Both hashes being 32 bytes does not make them interchangeable.
Keep v1 SHA-256 unambiguous. Reject an unsupported or altered selected algorithm;
do not silently fall back after grant issuance.

The existing grant binds the complete digest before transfer. A faster hash
does not eliminate that full source scan. Avoiding it requires a trusted
precomputed manifest for an immutable source or a separately designed change
to authorization. Likewise, retaining mandatory SHA-256 alongside BLAKE3 leaves
SHA-256 work on the critical path; dual hashing is useful for experiments, not
evidence that the old bottleneck disappeared.

## 3. Merkle trees and verified ranges

No application-level Merkle tree exists today. Packet AEAD proves that the peer
holding the key sent a packet; a root bound into the grant could additionally
prove that a range belongs to the authorized file before EOF.

Benefits to test: parallel range verification, authenticated resume, early
rejection of the wrong contents, and safe reuse of existing chunks. Trees do
not inherently reduce first-copy network bytes; manifests and proofs add bytes.

Start with fixed-size verification blocks independently of UDP datagram size.
Compare 256 KiB, 1 MiB, and 4 MiB blocks. This is simpler than introducing CDC,
resume, compression, and a new digest simultaneously.

Choose one precisely specified construction:

- Standard BLAKE3 identity with a verified-range encoding such as
  [Bao](https://github.com/oconnor663/bao/blob/master/docs/spec.md).
- A separately identified application Merkle construction using cryptographic
  leaf hashes and domain-separated parent nodes.

Do not concatenate ordinary BLAKE3 block digests and call their hash the
standard BLAKE3 digest of the file. BLAKE3 chaining values, positions, tree
shape, and root processing have specific semantics. The
[BLAKE3 specification](https://raw.githubusercontent.com/BLAKE3-team/BLAKE3-specs/master/blake3.pdf)
defines them. A custom manifest root is a different identity.

For either construction, the grant must bind the algorithm/scheme, file size,
root, and relevant layout parameters. Bound proof depth and metadata size;
reject wrong offsets, swapped leaves, missing coverage, malformed final blocks,
and roots or lengths inconsistent with the grant. Bao's final-chunk and length
validation rules require particular care. Fresh grants and keys are mandatory
for resume; do not revive an old nonce sequence or trust a stale bitmap.

## 4. macOS and Linux I/O

Apple's [kqueue interface](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kqueue.2.html)
reports events/readiness. It is not io_uring's general shared submission and
completion model. Go already integrates kqueue in its
[Darwin network poller](https://go.dev/src/runtime/netpoll_kqueue.go).

Apple's [Dispatch I/O](https://developer.apple.com/documentation/dispatch/dispatch-i-o?language=objc)
offers asynchronous descriptor operations. Its
[random-access channels](https://developer.apple.com/documentation/dispatch/dispatch_io_random?language=objc)
permit concurrent offset-based operations. That is an option to benchmark,
not a drop-in io_uring equivalent or a guaranteed improvement over Go workers.
Wrap an already securely opened descriptor; do not re-open an unchecked path.
Account for cgo/callback and buffer-lifetime costs if introducing libdispatch.

First implement a portable bounded worker pipeline behind the existing File
interface. Then compare native backends using the same workloads. Linux's
[io_uring design](https://kernel.dk/io_uring.pdf) is relevant to a later backend;
the repository currently submits no io_uring requests. Preserve privilege and
descriptor boundaries regardless of backend.

Another Linux experiment is UDP segmentation/receive offload, documented in
[udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html). GSO can submit several
already sealed equal-sized datagrams together; GRO must be split back into
individual frames before authentication. This can preserve v1 framing. It
must preserve datagram boundaries, partial-send accounting, pacing, and fallback
on unsupported hosts. It does not authorize exceeding the path MTU.

## 5. Lock-free rings and processing pipelines

Assuming “lock-tree” means lock-free: the UDP engine currently has a single
owner, so there is no contended engine lock to remove. Rings become useful
between newly separated stages. The
[DPDK ring documentation](https://doc.dpdk.org/guides/prog_guide/ring_lib.html)
illustrates bounded rings and distinct producer/consumer modes; this is a
design reference, not a recommendation to add DPDK or kernel bypass.

Prototype batch handoff over bounded Go channels first, then benchmark an
SPSC ring where the ownership really is single-producer/single-consumer.
A worker pool generally needs a different topology. Compare cache contention,
scheduling, allocations, CPU/byte, and cancellation latency; lock-free is not
synonymous with faster. Avoid one goroutine or queue operation per datagram
where a batch can be handed off instead.

Suggested sender stages:

```text
securely opened file -> bounded read-ahead -> hash/optional codec workers
                    -> packet sealing -> one congestion-controlled sender
```

Suggested receiver stages:

```text
socket batches -> authentication -> range reservation -> bounded writes
               -> write completions -> verification -> fsync/rename barrier
```

These are architectural proposals. Network pipelining already exists: several
packets can be outstanding without a per-packet RTT wait. Read-ahead is currently
synchronous and does not overlap file I/O with the rest of the engine.

Keep one owner for sequence allocation, congestion state, and the hole map.
Workers receive uniquely assigned work; a retry gets a fresh nonce. Reserve
missing ranges before dispatching concurrent writes so overlapping arrivals
cannot violate first-write-wins. Count delivery only after successful writes.
No worker may retain a scratch buffer after ownership passes to another stage.
Cancellation must drain or stop work before cleanup; commit waits for every
required write and verification completion. Separate control-service capacity
prevents data workers from starving PONG, FEEDBACK, NACK, or lease handling.

Bound memory in bytes across all stages, not only queue entries. An illustrative
64 slots of 256 KiB is already 16 MiB for one queue, before ciphertext, receiver
buffers, and worker-local state. Plaintext stays inside the authorized helper;
introducing a queue must not move it into the agent or relay.

With independent resources and sufficient buffering, overlapped stage time can
approach the slowest stage instead of their sum. Shared CPU, memory bandwidth,
storage, backpressure, and sequential hash dependencies limit that ideal.

## Recommended experiment sequence

| Order | Experiment | Compatibility | Main success measure |
| --- | --- | --- | --- |
| 1 | Bounded read/write/crypto pipeline and effective socket batches | Can retain v1 wire; implementation spec changes | End-to-end goodput, CPU/byte, bounded RSS, control latency |
| 2 | SHA-256 versus BLAKE3 backend comparison | Local benchmark first; new grant semantics for adoption | Preparation time and full-transfer time on amd64/arm64 |
| 3 | Fixed-block authenticated manifest / verified ranges | Experimental protocol and grant revision | Parallel verification and safe resume without rereading the full target |
| 4 | Tenant-scoped delta reuse, fixed blocks versus CDC | Experimental protocol and explicit reuse authorization | Total elapsed time and actual wire bytes for successive versions |
| 5 | Native async I/O and lock-free handoff | Can retain wire format | Improvement over the portable pipeline, not just an API microbenchmark |

Also retain selective delivery credit as a transport priority: noteContig still
holds flight credit for delivered bytes above a hole. A Merkle tree does not
fix that accounting. Separate compressed, sparse, random, and repeated-version
workloads; the older compression study used a 40 MB/s model predating the latest
overhaul and must be remeasured before its projected gains guide implementation.

Every experiment reports preparation, time to first byte, sustained transfer,
verification/commit, payload and wire bytes, retransmissions, CPU, peak memory,
and disk traffic. Compare warm and cold caches, clean and lossy paths, slow
storage, and both architectures. Inject forged proofs, wrong algorithms,
cross-tenant reuse, changed basis files, duplicate/overlapping completions,
short I/O, expiry, and cancellation. Acceptance requires the existing security
negatives and new feature-specific failures to remain fail-closed.
