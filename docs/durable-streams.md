# Durable processed-event streams — proposed contract

Status: local storage prototype plus proposed network contract, 2026-10-22.
Selected first streaming use case. Not wired into SystemAPI or the network, and
not an extension silently accepted by
v1 file grants. The release tracks and controls are in `platform-roadmap.md`.

## Local prototype contract

`internal/streamlog` implements one locally authorized partition and one consumer.
The operator supplies an existing private directory and opaque tenant, stream,
partition and schema IDs. It uses safeio path confinement and an exclusive
directory lock; a second writer is refused. This is not a stream grant validator.
There is no network listener, privilege elevation, automatic token file, or
at-rest encryption. Use synthetic data in the harness; production spools require
the deployment controls in the roadmap.

The log is append-only immutable segments, not an in-place WAL. Each segment has
a versioned, bounded binary envelope, a previous-segment hash, an operation
(fence, append, consumer checkpoint), and SHA-256 integrity. A fixed-size,
checksummed checkpoint binds identity, segment count and chain head. Write
segment through a 0600 temp, fsync, rename, fsync directory; then replace the
checkpoint by the same sequence. Only then return a persisted receipt. Neither
the checkpoint nor the hash chain is protection against a malicious local
writer who can rewrite both; external signed anchors remain future work.

Recovery validates every committed segment and sequence before returning a
usable log. Missing/truncated/corrupt committed history fails closed. Bytes
beyond the checkpoint are uncommitted: a segment at the next transaction number
may be overwritten, and fixed staging names may be cleaned under the lock.
Recovery never guesses an earlier checkpoint to hide corruption. After an I/O
failure the handle is poisoned; close/reopen determines whether the transaction
committed. An acknowledgment lost after checkpoint persistence is safe to retry.

Fences strictly increase a producer epoch; new epochs restart record sequence at
1. They are durable transactions; older epochs cannot append. Consumer cursors
remain scoped to known epochs so retained records can finish after rollover.
The caller must resolve any unpersisted old-producer outbox before authorizing
rollover; this prototype cannot reconcile an unavailable producer's private outbox.
An append batch is contiguous, all-new or an exact retry of a
previously persisted range. Identical retries succeed without new writes;
conflicting duplicates, mixed old/new batches, and sequence gaps are rejected.
Empty payloads are allowed, empty batches are not. The schema is bound by the
partition identity and payloads remain opaque. Replay takes an explicit epoch
and sequence, returns bounded pages, and returns a gap for an unavailable range.
One caller-declared processed cursor is durable per epoch; it cannot advance
beyond persisted data or regress. The library does not execute business effects
or claim that cursor persistence makes external effects exactly once.

Hard parser ceilings: payload 1 MiB, batch 8 MiB, 1,024 records per batch,
1,000,000 records and 1,000,000 transactions per log; configured quotas can be
lower. Quotas cover committed encoded bytes, records, and transactions. One
staged segment and a possible uncommitted next segment add at most two segment
bounds plus two checkpoint bounds; fixed temp names prevent repeated failures
from accumulating unique staging files. There is no retention eviction or
compaction yet: capacity exhaustion rejects writes without deleting history.
One metadata entry per retained record supports bounded replay and deduplication;
recovery memory is proportional to configured record/transaction limits.

The synchronous API accepts one bounded batch at a time. Successful append
returns persisted state and checkpoint evidence, never processed state. Explicit
consumer checkpoint returns processed state as declared by the caller. Segment
operation metadata supplies durable local audit evidence; signed export,
administrative access audit, tenant-wide quotas and audit outbox integration
remain future work. No record payload is printed by the harness.

### Prototype on-disk format (version 1)

All integers are unsigned little-endian. This is a local format, not a network
frame. Segment filenames are `segment-` followed by a zero-padded 20-digit
transaction number, starting at 1. `checkpoint` is the only committed head.
Fixed staging IDs are `xfr_stream_segment` and `xfr_stream_checkpoint` under
safeio's reserved temp naming. Known initialization staging can be removed
under the lock; a missing checkpoint with remaining history fails closed.

| Segment offset | Bytes | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `SAHSLOG1` |
| 8 | 1 | Operation: 1 fence, 2 append, 3 processed checkpoint |
| 9 | 7 | Reserved, must be zero |
| 16 | 8 | Transaction number |
| 24 | 8 | Producer epoch |
| 32 | 8 | First record sequence / processed sequence; zero for fence |
| 40 | 4 | Record count; zero except append |
| 44 | 4 | Encoded body length |
| 48 | 32 | Previous segment SHA-256; zero for the first segment |
| 80 | variable | Append records: u32 payload length then payload, repeated |
| end minus 32 | 32 | SHA-256 of every preceding segment byte |

The 112-byte checkpoint is magic `SAHSCPT1` (8), identity digest (32),
transaction count (8), chain head (32), and SHA-256 of the first 80 bytes (32).
Identity digest is SHA-256 over `sahxfer-stream-identity-v1\n` followed by tenant,
stream, partition and schema in that order, each encoded as u32 byte length and
UTF-8 bytes. IDs are nonempty, at most 128 bytes, valid UTF-8, without ASCII
control characters; no Unicode normalization is performed. Quotas are operator
configuration and are checked again during recovery, not silently raised.

`Open` syncs the recovered directory before returning, covering process death
after a visible checkpoint rename but before its directory sync. Process-exit
tests do not simulate power-loss ordering or storage devices ignoring fsync.
All writers must honor the advisory lock; this is not a distributed lease.
Quotas cover this store's committed segments, not arbitrary unrelated files in
the operator-supplied directory. No compaction or outbox eviction ships yet.

### Run the synthetic producer/consumer harness

```sh
go run ./cmd/streamlab -records 1024 -record-bytes 4096 -batch 64
go test ./internal/streamlog ./cmd/streamlab
go test -race ./internal/streamlog ./internal/safeio ./cmd/streamlab
go test ./internal/streamlog -run '^$' -fuzz '^FuzzRecoveryParser$' -fuzztime=10s -parallel=2
go test ./internal/streamlog -run '^$' -bench BenchmarkDurableAppend -benchtime=3x -count=3
```

The harness creates and removes private temporary outbox/sink directories,
generates synthetic bytes, simulates a lost persisted acknowledgment and a
consumer restart before processed-checkpoint persistence, and verifies all
payloads after replay. It prints counts and timing, never record contents.
`replayed_records` includes deliberate redelivery. Consumer verification is a
synthetic idempotent operation, not exactly-once external side effects. Unit
tests additionally terminate subprocesses at each persistence barrier,
bypassing all deferred cleanup.

### Initial validation and measurements

The full repository suite passed on Darwin amd64 and Linux, including the
existing file-protocol fail-closed cases. Race checks passed for streamlog,
safeio and streamlab, including the final producer/consumer rollover correction.
`go vet ./...` passed. A 10-second, two-worker parser fuzz run completed 637,776
executions without failure. The parser also has direct tests for re-signed
invalid fields and an oversized encoded payload length.

On Darwin amd64, Intel i9-9880H, Go 1.27.3, three runs of three appends each,
4 KiB per record, produced these local durable-append results:

| Records per batch | Payload per batch | Mean time per append across runs | Goodput |
| --- | --- | --- | --- |
| 1 | 4 KiB | 40.5–41.1 ms | 0.10 MB/s |
| 64 | 256 KiB | 43.8–44.7 ms | 5.86–5.98 MB/s |
| 256 | 1 MiB | 52.6–54.6 ms | 19.21–19.94 MB/s |

These include segment and checkpoint file/directory persistence and exclude
initial store creation, fencing, replay and networking. They are small-sample
local measurements, not p99 latency, replicated durability, or a comparison
against an established streaming service. The benchmark demonstrates durability
cost and batching tradeoffs; it does not establish low-latency financial-feed
suitability. The 1,024-record synthetic harness also stores an outbox, checkpoints
consumer progress, reopens stores, and deliberately redelivers records, so its
runtime is not the append-only throughput figure above.

Remaining before network release: stream grants and consumer authorization,
network framing/credit, reconnect session keys, retention/compaction and outbox
eviction, replication, encrypted spool deployment, signed audit export, and
crash/power-loss testing on supported production storage. Future analytics and
bulk AI release tracks remain in `platform-roadmap.md`.

## What is transferred

Processed financial events, features, or structured data batches from one
authorized producer to one authorized durable sink initially. This is not an
exchange order-entry protocol, a matching engine, or a global transaction log.
Fan-out and replicated durability are later explicit extensions. Existing files
remain one-file grants with size/hash/rename completion.

Streams are finite-lived sessions over potentially unbounded logical datasets.
Each session has grant expiry/renewal, bounded bytes and duration, and fresh key
material. No nonce space or permission survives indefinitely across reconnects.
The control plane grants access and audits it; payloads stay off the WebSocket.

## Identity, ordering, and authorization

Logical record identity is `(tenant, stream, partition, producer_epoch, sequence)`.
The control plane fences producer epochs; old epochs cannot append after a
replacement is authorized. Sequence is monotonically increasing per partition.
No global order across partitions is promised. Event time and ingestion time are
distinct metadata; neither replaces sequence for delivery correctness.

A new stream-specific grant must bind tenant, resource/partition, producer or
consumer identity, purpose, epoch, transport, schema policy, payload/record caps,
duration, acknowledgment policy, and replay range/retention permissions.
File grants must be rejected for stream operations and vice versa. Subscribe
and replay are distinct permissions. The exact envelope/wire encoding and
lease vectors need review before implementation. Do not invent compatibility by
repurposing a v1 DATA flag, file offset, or DONE hash.

## Records and batching

A record/batch envelope carries version, partition identity, epoch, sequence or
bounded sequence range, schema identifier/version, encoding, bounded payload
length, and event-time metadata when meaningful. Explicitly define empty records,
fragmentation/reassembly limits, oversized-record rejection, numeric overflow,
and schema mismatch before implementing the parser. No unbounded allocation
from a declared length. Reject unknown mandatory fields and unsupported versions.

Support opaque application bytes initially; evaluate Arrow IPC record batches
for typed analytics. Payloads are never interpreted as commands or model code.
Batch by both byte limit and maximum age so a throughput optimization cannot
starve a low-volume stream. Publish the batch settings with latency measurements.

Separate transport packet sequence (nonce and replay protection) from durable
record sequence. Re-sending a record always uses a fresh packet nonce. Source
bytes for a given record identity are immutable; conflicting duplicate content
is an error. Content identity uses a cryptographic digest, never xxHash alone.

## Delivery and durability

Expose three distinct states: received/authenticated, persisted, and application
processed. Network feedback controls packet delivery and does not certify disk
durability or downstream processing.

The initial promise is at-least-once delivery within the authorized retention
window, with stable record IDs for idempotent consumers. A durable acknowledgment
names the highest contiguous persisted sequence in a partition plus its epoch.
It is issued only after data and the relevant checkpoint are recoverably durable.
Specify local fsync versus replicated quorum explicitly; initial prototype
durability is local disk only and does not survive loss of that disk/node.

On crash after persist but before acknowledgment, replay may redeliver the
record. Deduplication state must recover consistently with the stored records.
Do not acknowledge across a missing sequence. If old content has expired,
return an explicit gap with the earliest available position. The consumer must
request a permitted snapshot/recovery action; it never silently skips ahead.

The producer retains a bounded durable outbox until persisted acknowledgment.
The sink maintains a durable append log and checkpoint. Recovery validates
record framing/integrity, truncates only an uncommitted torn tail, and reports
corruption in committed history. All spool and recovery paths require the same
confinement, privilege separation, quotas, and at-rest policy as other data.

Exactly-once application side effects are not provided by network acknowledgments.
A consumer needs an idempotent operation or a transaction that commits its
side effect and consumer position together. The platform must not mislabel a
transport-level duplicate filter as exactly-once business processing.

## Backpressure, quotas, and concurrency

Receiver credit covers bounded unpersisted bytes and records; congestion control
separately covers network capacity. Persist completion replenishes durable-input
credit. A stalled disk cannot create unlimited memory queues or optimistic ACKs.
Reserve bounded capacity for acknowledgment, renewal, cancellation, and errors.

Bound every queue and spool by bytes and entries. Quotas apply per tenant and
stream plus a global admission ceiling. If a durable consumer falls behind the
retention budget, block/reject according to policy or report explicit loss of
replay coverage; do not evict required records silently. Legal holds and deletion
requirements must have explicit policy precedence and operator visibility.

Parallelize across partitions with one ordering owner per partition. Share path
congestion budgets and schedule fairly across grants. Worker pools can perform
disk/crypto jobs but cannot independently assign packet nonces or commit stream
positions. Reconnects obtain fresh session material and authenticate their
requested cursor. Bounded replay cannot turn a grant into an unlimited read.

## Audit and failure semantics

Link grant intent to durable checkpoint evidence and result/termination events.
Record actor, policy version, opaque resource IDs, epoch/sequence ranges, unique
record/byte counts, and reason codes. Never place payloads, patient/account
identifiers, secrets, or unrestricted user metadata in logs. Audit export access
is tenant-scoped and audited itself. Checkpoint audit records should participate
in the durable outbox, with idempotent export and a bounded outage policy.

Required scenarios before release: tampered records; expired/wrong-purpose/wrong-
tenant grants; old epochs; duplicate IDs with different content; missing ranges;
sequence/length overflow; revoked replay permission; source/sink crash at each
durability barrier; disk full; truncated tail; corrupted committed history;
slow consumer; reconnect; replay outside retention; cancellation; audit sink
failure; and fresh keys/nonces on every session replacement.

## Evaluation references

[Arrow Flight](https://arrow.apache.org/docs/format/Flight.html) organizes data
exchange around Arrow record-batch streams. It is a format/API comparator for
structured data, not proof this transport needs to replace gRPC.
[JetStream](https://docs.nats.io/concepts/jetstream) supplies persistence, replay,
and consumer delivery tracking. Compare equal durability policies. Reuse an
established log service if it satisfies the workload; a custom log needs a
demonstrated advantage and independent recovery/security review.
