# File transfer, streaming, and agent-controlled data movement

Date: 2026-10-22. Living research and product hypothesis, not a claim of shipped
service capabilities or superiority over other protocols. Implementation:
Go, `github.com/afterdarksys/sahxfer`. Protocol authority remains
[the v1 design](docs/design.md); release order remains
[the platform roadmap](docs/platform-roadmap.md).

## The product case

The opportunity is a reusable data movement service that lets a person,
application, or AI agent authorize a bounded job, move bytes outside the
control channel, and receive evidence of what became durable and what was
processed. Products can reuse identity, policy, recovery, and result handling
instead of assembling a new copy script and status database for every workflow.

sahxfer supplies an initial file-transfer engine for that service: one file,
one grant, encrypted offset-addressed datagrams, repair, hash verification,
and durable publication. Whether its transport beats tuned alternatives on
customer networks is an open measurement question. A useful control contract
can remain valuable even where an existing transport wins.

AI data workflows are a target, not evidence of a market gap by themselves.
Test concrete jobs: a checkpoint delivered before a worker starts; a dataset
version made visible only after all objects verify; processed events replayed
after a consumer restart. Measure time until useful work can safely begin,
operator intervention, failure recovery, and cost, alongside MB/s.

## FTP, SFTP, SCP: what we actually compare

| Candidate | Transfer mechanism | Comparison purpose | Matched speed evidence here |
| --- | --- | --- | --- |
| FTP, binary mode | Separate TCP control/data connections; base FTP does not provide transport encryption | Lab-only plaintext reference | Not measured |
| FTPS, protected data channel | FTP with TLS protection negotiated for data as well as control | Encrypted FTP baseline | Not measured |
| SFTP over SSH | Pipelined file operations over encrypted SSH | Main deployed secure-file baseline, defaults and tuned | Not measured |
| Modern OpenSSH `scp` | SFTP over SSH by default | Familiar CLI baseline; do not count it as a different transport | Not measured |
| `scp -O` | Legacy SCP protocol over SSH | Explicit legacy compatibility case | Not measured |
| sahxfer UDP | ChaCha20-Poly1305 datagrams, NACK repair, pace-bbr | Granted single-file transfer | Local figures below; no matched competitor run |

FTP's control/data separation predates sahxfer; separation alone is not novel.
See [RFC 959](https://www.rfc-editor.org/rfc/rfc959) and
[FTP over TLS, RFC 4217](https://www.rfc-editor.org/rfc/rfc4217).
Modern `scp` uses SFTP by default; `-O` explicitly selects the legacy protocol.
Record the installed OpenSSH version and actual mode in every result.
[OpenSSH scp manual](https://man.openbsd.org/scp).

There is no honest universal “FTP = X MB/s, SFTP = Y MB/s” table. Hardware,
RTT, windows, cipher implementation, storage, and completion semantics can
change the ranking. Populate the pending rows using the same files and hosts.
Do not treat unencrypted FTP as a security-equivalent competitor.

## Measured sahxfer baseline

Darwin amd64, Intel i9-9880H, Go 1.27.3, local APFS temporary files, warm-cache
setup, loopback UDP, random contents, 8 MiB granted send/receive buffers at both
ends. Decimal MB/s throughout; file sizes below use binary MiB/GiB. These runs
include both initial source hash passes and durable commit in end-to-end time.
The transfer interval excludes preparation and commit, but includes startup,
receiver writes, repair, and streaming/final verification. It is not wire rate.

| File / profile | Source pipeline | Samples | Median end-to-end MB/s | Median transfer-interval MB/s |
| --- | --- | --- | --- | --- |
| 256 MiB / internet | Off | 3 | 65.56 | 96.10 |
| 256 MiB / internet | On | 3 | 65.49 | 96.71 |
| 256 MiB / dc | Off | 3 | 95.71 | 186.90 |
| 256 MiB / dc | On | 3 | 94.54 | 183.50 |
| 2 GiB / internet | Off | 1 | 63.59 | 91.59 |
| 2 GiB / dc | Off | 1 | 101.57 | 199.00 |

The single-sample rows are observations, not stable estimates. At 2 GiB,
internet took 33.77 s: preparation plus attachment about 10.30 s, transfer
23.45 s, commit 29 ms. DC took 21.14 s: preparation plus attachment about
10.32 s, transfer 10.79 s, commit 26 ms. Shared CPU/cache and overlapping
sender/receiver work prevent treating isolated stage throughputs as additive.

The larger datagrams improved this local workload substantially. That does
not establish performance through a physical NIC or a routed path; DC remains
restricted by tenant-network policy. The source pipeline still has no demonstrated
advantage in this small sample set. Retain its experimental default-off status.

Raw evidence: [256 MiB samples](docs/benchmarks/2026-10-22-transfer/timing.txt),
[2 GiB samples](docs/benchmarks/2026-10-22-transfer/2gib-timing.txt),
[CPU report](docs/benchmarks/2026-10-22-transfer/network-cpu-top.txt),
and [allocation report](docs/benchmarks/2026-10-22-transfer/alloc-top.txt).
[Lab instructions](docs/performance-lab.md) define timing and profiler boundaries.

## Where bottlenecks live

| Layer | Failure to fill capacity | Evidence or experiment |
| --- | --- | --- |
| Source preparation | Full-file hash delays first transfer; revalidation rereads source | Two scans cost about 10.3 s for this 2 GiB fixture; preserve change detection |
| Application requests | Too little outstanding work for RTT | Compare default and tuned SFTP request depth/buffer size |
| Transport windows | Flight/receive window below bandwidth-delay product | Measure RTT, effective windows, and feedback cadence on both transports |
| Packet processing | Authentication, allocation, copying, and writes per datagram | Compare payload profiles and CPU stacks; avoid assuming cipher is dominant |
| Scheduling and batching | Small effective socket batches or timer wake overhead | Execution trace plus actual batch sizes and syscall attribution |
| Destination | Slow writes, out-of-order hash reads, or durable commit | Separate arrival/write/verification/commit; include slow-storage cases |
| Recovery | Lost acknowledgments, missing prefixes, expired sessions | Measure retry bytes, time to recover, and whether completion remains truthful |
| Processing | Sink or model consumes slower than the network | Measure consumer lag and enforce bounded backpressure |

OpenSSH SFTP documents 64 outstanding requests and a default 32 KiB buffer:
roughly 2 MiB of request payload in flight. Our illustrative calculation at
50 ms is 2 MiB / 0.05 s = 41.94 MB/s if this request window is limiting.
This is not a measured or intrinsic SFTP ceiling: tune and verify both ends.
SFTP also offers an upload flush request where the server supports its fsync
extension. [OpenSSH sftp manual](https://man.openbsd.org/sftp).

For perspective, 10 Gbit/s at 50 ms requires about 62.5 MB in flight.
The illustrative application-window calculation and this bandwidth-delay
calculation expose different possible limits; neither predicts an actual run.
[RFC 6349 throughput methodology](https://www.rfc-editor.org/rfc/rfc6349).

TCP presents an ordered byte stream, so a missing segment can hold back later
bytes from the application. It still buffers out-of-order segments and repairs
loss; it does not retransmit every subsequent byte by definition.
[TCP specification, RFC 9293](https://www.rfc-editor.org/rfc/rfc9293).
sahxfer can authenticate and write later file ranges while repairing a hole.
However, its current contiguous-prefix flight accounting can still withhold
credit behind that hole. The architecture creates an opportunity, not proof
that current sahxfer wins on loss.

The new aggregate CPU profile across four 256 MiB cases shows substantial
socket and file syscall stacks, including receiver `onData` writes. It does
not isolate one payload profile or prove syscall time is the sole bottleneck.
The sampled allocation profile attributes about 93% of allocated bytes to
`Peer.classify`; these are cumulative allocations, not retained memory or RSS.
Together these justify separate receiver-write and outgoing-buffer experiments.
They do not establish that removing allocations produces a proportional speedup.

## The comparison experiment

Use the same two physical Linux hosts, source file, destination filesystem,
network path, and concurrency. Record TCP congestion control, cipher, MTU,
client/server versions, socket limits, cache conditions, and CPU utilization.
Begin with 2 GiB and a file large enough for at least a minute of steady transfer.
Use random, zero-heavy, compressible, and already-compressed fixtures separately.

Run FTP, protected FTPS, SFTP defaults/tuned, modern SCP, explicitly legacy SCP,
and sahxfer internet/DC where authorized. Compression is off for the baseline;
report compressed experiments separately. Include HTTPS as a product-relevant
baseline in the next extension. Compare single flows first, then competing
flows; consuming more than a fair share is not a transport win.

Report two outcomes: native command completion and equivalent verified durable
publication. For the latter, stage to a temp destination, verify the complete
hash/size, persist data, rename, and persist the directory with a test wrapper
where a tool does not supply those guarantees. Include all wrapper work in
that measurement. Client success or an SFTP flush request alone is not evidence
of identical atomic-publication semantics.

Collect at least five samples per scenario, alternate test order, preserve
failures, and report ranges and medians. Test clean paths, controlled RTT,
random/burst loss, reorder, reverse-path loss, slow storage, and disconnects.
Report payload/wire bytes, retransmissions, CPU seconds/GiB, RSS, disk traffic,
time to first data, completion latency, and recovery. Add fault tests for
wrong contents, partial writes, cancellation, and target preservation.

**Pending:** host addresses and dedicated test directories. No FTP/SFTP/SCP
speed comparison has been executed in this work. Do not publish a competitive
speed claim until those rows have matched measurements.

## Agent-driven transfer and processing

An agent should request a named outcome and receive a durable job identity,
not construct shell commands containing credentials or handle file contents
inside its conversation context. This is a proposed service API around the
engines, not an implemented SDK or a new v1 wire field.

| Proposed operation | Required contract | Present status |
| --- | --- | --- |
| Plan and authorize | Resolve resource IDs; bind tenant, purpose, source/destination, caps, deadline | File grant design exists; SystemAPI wiring remains separate |
| Start or inspect job | Idempotent submission; stable job ID; typed status/reason codes | Durable cross-process job API not implemented |
| Cancel or renew | Enforce authority and budgets; report races with already committed work | File agent control channel has renew/cancel; broader job API proposed |
| Subscribe or replay | Bounded stream/partition/epoch range; explicit gap; stable record IDs | Local stream prototype; network grants and service pending |
| Record processing | Persist a consumer cursor separately from durable ingestion | Local caller-declared checkpoint exists; external effects are not proven |
| Publish dataset version | Verify all objects before atomic manifest publication | Future roadmap; v1 remains one file per grant |

Keep distinct states: accepted, transferring, persisted, verified/published,
and processed, with failed/cancelled outcomes. These are a proposed job model;
not every state applies to both file and stream operations. Receiving bytes
is not persistence. Persistence is not model ingestion. A processed cursor is
a consumer declaration, not evidence that an external database transaction or
GPU computation happened exactly once.

The processing system should schedule explicitly authorized, versioned workers
around the data path. Bind input versions, transform identity, resource budget,
output destinations, and provenance. Received payloads remain untrusted data;
they cannot alter policy, invoke tools, or choose executable code. The transport
helper must not become a general-purpose processor or lose its privilege boundary.
Keep the agent process that owns the UDP socket free of grant keys/plaintext;
processing belongs in a separately authorized execution environment.

Backpressure must reach the producer when storage or consumers fall behind.
Bound RAM, spool bytes, replay range, worker concurrency, and operation duration.
For durable events, reject or pause at exhausted capacity with an explicit
reason. A future latest-value feed may supersede updates only under its own
contract. Dataset bytes, record batches, and manifests stay off the SystemAPI
WebSocket; that channel carries grant and audit control.

This direction builds on [the durable-stream prototype](docs/durable-streams.md):
local immutable segments, durable checkpoints, retry deduplication, producer
fencing, and bounded replay. It currently has no network listener, stream grant
validation, retention eviction, replication, or at-rest encryption. Its local
storage evidence must not be marketed as a distributed processing service.

## Build the missing contract; reuse established systems where they fit

Arrow Flight already supplies high-performance RPC for Arrow record batches,
including discovery and data endpoints. It is a meaningful structured-data
comparison and possible integration boundary.
[Apache Arrow Flight](https://arrow.apache.org/docs/format/Flight.html).
JetStream already supplies persistence, consumers, replay, and at-least-once
delivery. Compare equal retention, storage, and replication policies before
building a competing stream service.
[NATS JetStream](https://docs.nats.io/concepts/jetstream).

The differentiation to prove is a coherent product contract across movement,
authorization, recoverability, processing state, and audit in SAH-managed
workflows. Neither UDP nor “AI-ready” is a defensible differentiator by itself.
A connector to an existing log or data service may deliver that contract sooner
than a new transport for every workload.

## Release sequence and decision gates

1. Finish physical-host file comparisons and identify the dominant bottleneck.
   Accept an optimization only with matched results and fail-closed validation.
2. Continue the approved durable-event track: specify network grants, bounded
   framing/credit, reconnect keys, replay, and failure behavior around the local
   prototype. Evaluate existing stream infrastructure alongside it.
3. Define a small agent-facing job API and pilot one workflow: move a checkpoint,
   verify publication, then authorize a worker to consume that exact version.
   Specify idempotency, cancellation races, retry classification, and receipts
   before exposing it as an automated tool.
4. Add structured-data connectors and processing receipts, then the roadmap's
   distinct fresh-update and versioned multi-file dataset capabilities. Resume,
   manifests, and new hash algorithms need explicit protocol/grant revisions.

Pilot success means an agreed delivery/processing SLO, bounded resources,
recovery without silent gaps or false success, and less integration/operational
work than the baseline. File-transport speed and workflow usefulness are
separate acceptance criteria. This research does not change the SystemAPI repo,
the suite Wired join, the existing login, or the v1 cryptographic contract.
