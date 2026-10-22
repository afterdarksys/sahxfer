# Data movement platform roadmap

Date: 2026-10-22. This records the approved product direction. It does not
describe capabilities that have already shipped. The v1 file protocol remains
`docs/design.md`; SystemAPI integration still requires its own repository change.

## Product direction and release order

Move large datasets and continuous data feeds quickly, with verifiable delivery,
tenant-scoped authorization, provenance, and an exportable audit trail. Target
AI datasets/checkpoints, medical datasets, and processed financial data. Size
alone is not the differentiator: predictable recovery, latency, and evidence of
delivery are part of the product. Transport must never execute received models,
documents, code, or instructions embedded in data.

The user selected durable processed events with replay and no silent gaps as
the first streaming use case. Preserve the other two tracks for later releases:

| Track | Delivery contract | Status / order |
| --- | --- | --- |
| Existing file transfer | One granted file, verified hash, durable replacement | Implemented baseline, ongoing performance work |
| Durable processed events | Per-partition order, persisted acknowledgment, replay, explicit gaps | Local storage/harness implemented; network integration next |
| Fresh-update analytics | Explicit supersession and bounded staleness; snapshots recover state | Future release after durable streams |
| Bulk AI datasets/checkpoints | Versioned manifests, verified resume, atomic dataset publication | Future release after durable streams; single files already work |

The latter tracks are committed roadmap scope, not interchangeable flags on
durable delivery. Their release dates and performance SLOs are not yet set.

## Engineering milestones

### A. Measured v1 transport improvements

In this change: remove temporary nonce allocations, avoid UDP address string
comparison, add caller-owned sealing and a bounded returned-packet cache, retain
the opt-in source pipeline, and publish before/after measurements. Packet cache
ownership ends only after synchronous send completion or error. Do not claim a
zero-allocation engine: classification and other metadata still allocate.

Next: profile receiver write batching, reserve ranges before asynchronous jobs,
credit only successful writes, bound completion queues, and drain before hash/
fsync/rename. Compare sparse, full, and incremental file reservation before
selecting a policy. Physical preallocation can defeat ZERO's storage savings.

Then specify selective delivered-range accounting to release credit above a
missing prefix, including retransmission and ZERO accounting. Never infer a
particular delivered range solely from a total delivered-byte count. Keep one
congestion budget per path; crypto workers do not get independent send windows.
Retain single-owner sequence, hole, and congestion state. Introduce lock-free
queues only if measured contention warrants their complexity.

Gate: fail-closed suites on supported OSes, race tests, bounded cache evidence,
byte-for-byte transfer verification, CPU/allocation profiles, and honest goodput
comparisons including preparation and durable commit.

### B. Durable event-stream prototype

Implemented local milestone: immutable append segments and atomic checkpoints,
exclusive writer lock, bounded parsing/quotas, producer epochs, deduplicated
retries, bounded replay, distinct persisted/processed cursors, and a synthetic
producer/outbox/consumer harness. Crash-boundary and corruption tests cover this
local disk contract. Local audit metadata is available; signed export and the
control-plane audit outbox are not implemented.

Next implement the network portions of `docs/durable-streams.md`: bounded framing,
partition sequence and producer fencing, durable log, reconnect/replay, receiver
credit, and distinct received/persisted/processed states. Start with a local
fault-injection harness (now present) and explicit bootstrap authorization. No public stream
service until the grant API and agent integration land in their own change.

Gate: crash injection before/after append, fsync, acknowledgment and checkpoint;
duplicate delivery; reorder; gaps; expired or wrong-purpose grants; wrong tenant;
old producer epoch; nonce renewal; disk-full; consumer lag; retention exhaustion;
cancel; revocation; and reconnect. No silent skips or success before durability.

### C. Audit, operations, and deployment profiles

Provide control-plane intent/denial, start, renewal/revocation, durable checkpoint,
completion/abort, retention change, replay request, and administrative-access
events. Each event carries schema version, event ID, tenant, actor/service ID,
grant/session ID, resource ID, policy version, timestamp, outcome, reason code,
and applicable byte/record counters. Treat identifiers and timestamps as
sensitive metadata; never log payloads, credentials, tickets, route tokens or
grant keys. Prefer opaque dataset IDs over patient/account identifiers or paths.

Make audit delivery durable through an outbox and idempotent ingestion, with
explicit sink-outage behavior. Admission fails when required intent cannot be
persisted. Checkpoint audit may be committed with the data/checkpoint transaction
and exported asynchronously; define a bounded outage budget before release.
Correlate source and destination receipts without claiming receipt proves the
consumer processed data. Export signed, versioned evidence bundles; retain keys
and verification metadata needed to validate historical signatures.

An append-only hash chain alone cannot prevent a privileged operator from
rewriting the entire chain. Tamper evidence needs external signed checkpoints
or independently controlled immutable storage, separation of duties, and tested
backup/restore. WORM/retention-locked storage must be an actual deployment
capability, not a property claimed from the packet protocol.

Profile requirements: customer identity mapping, least privilege, encryption at
rest for spools and checkpoints, key management and rotation, residency-aware
routing/storage, retention/legal holds, deletion evidence, incident response,
backup/recovery drills, export access controls, and security review. Encrypted
relays still expose traffic metadata. No cross-tenant deduplication oracle.

Healthcare applicability must be assessed for the operator and workflow.
HIPAA involves administrative, physical, and technical safeguards; audit
controls and applicable business-associate agreements are not supplied by a
fast encrypted transport. Consult [HHS Security Rule guidance](https://www.hhs.gov/hipaa/for-professionals/security/index.html),
[HHS audit controls](https://www.hhs.gov/hipaa/for-professionals/compliance-enforcement/audit/protocol/index.html),
and [NIST SP 800-66 Rev. 2](https://csrc.nist.gov/pubs/sp/800/66/r2/final).

Financial applicability depends on entity, jurisdiction, and record type.
For relevant US broker-dealer records, SEC electronic-recordkeeping requirements
include specific WORM/audit-trail alternatives and associated preservation and
production requirements; a transfer log is not a substitute for the full record
system. See the [SEC rule and associated materials](https://www.sec.gov/rules-regulations/2022/10/electronic-recordkeeping-requirements-broker-dealers-security-based-swap-dealers-major-security).
These references guide control mapping, not a certification or legal conclusion.
Deployment-specific counsel/control-owner review remains a release gate.

### D. Fresh-update analytics (retained future scope)

Define key-based supersession, event time versus ingestion time, freshness
deadlines, explicit dropped/superseded counters, and snapshot-plus-delta recovery.
Keep this purpose separate from durable financial records: clients cannot
silently turn a no-gap subscription into a lossy latest-value feed. Measure
age-of-information and p99 freshness under bursts, not just aggregate bytes/s.

### E. Bulk AI datasets and checkpoints (retained future scope)

Specify immutable dataset versions, bounded manifests, per-object strong hashes,
verified resume with fresh grant material, atomic manifest publication, lineage,
schema/dtype/endianness, and reproducible source identifiers. No partial dataset
becomes current. Keep hash negotiation explicit; evaluate BLAKE3 and authenticated
chunk trees before changing the grant. CDC reuse follows fixed-block reuse and
must be tenant-authorized. Arrow record batches are a candidate for structured
data; opaque model artifacts remain opaque. Neither format implies safe content.

## Benchmark and commercial release gates

Compare file transfer against HTTPS/SFTP and suitable QUIC implementations with
equivalent encryption, source preparation, and durability. Compare structured
batch delivery with [Arrow Flight](https://arrow.apache.org/docs/format/Flight.html)
and durable event delivery with [JetStream](https://docs.nats.io/concepts/jetstream)
or another established durable log, with equal acknowledgment/replication rules.
Do not present durable single-node results as equivalent to replicated storage.

Record payload sizes, entropy, offered load, achieved load, batch age/size,
warm/cold caches, storage, CPU/architecture, RTT/jitter/loss, and replication
factor. Report goodput, wire overhead, CPU/byte, allocations, peak RSS, disk I/O,
time to first data, p50/p95/p99 durable acknowledgment latency, catch-up rate,
reconnect time, duplicate count, and gap detection. Test shared links and fairness;
several flows cannot be counted as a win merely by taking more bandwidth.

Commercialization follows evidence: managed operations, enterprise identity,
private deployment, retention/replay tiers, audit export, and measured SLOs.
Meter separately unique accepted bytes/records, replay delivery, retained
byte-hours, and total wire bytes. Make retry accounting explicit and idempotent;
lost acknowledgments must not duplicate ingestion charges. Do not bill a
delivered or processed outcome that only exists as a send attempt.

Gate: customer pilot with a named workload and agreed SLO, failure/recovery
exercise, external security assessment, applicable control evidence, support
runbooks, and transparent pricing measurements. No universal "fastest", "AI
ready", "compliant", or exactly-once processing claim without corresponding
measured capabilities and deployment evidence.
