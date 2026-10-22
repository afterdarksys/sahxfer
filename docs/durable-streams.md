# Durable processed-event streams — proposed contract

Status: design proposal, 2026-10-22. Selected first streaming use case. Not
implemented, not wired into SystemAPI, and not an extension silently accepted by
v1 file grants. The release tracks and controls are in `platform-roadmap.md`.

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
