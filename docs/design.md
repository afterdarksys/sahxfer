# sahxfer design

Status: working spec for this repo, 2026-10-14. Not in the suite Wired join. Congestion in this implementation is pace-bbr (section 6), not a byte-identical BBRv3. The portable I/O path is `pread`/`pwrite` (section 7.3). Change the spec by editing this file before the code that follows it.

**sah** means Service Automation Hub. Authorization reuses SystemAPI, the outbound agent, and the `sahconnect` device-login bearer. The byte path is new.

Threats: this design defends a granted copy against a forged packet, a replay, a path escape, a partial file at the target path, a read grant used to write, and a relay that tries to read the file. It does not defend what `pty_user` may legitimately write inside an allowed root, a hard link out of that root, disk failure after `DONE`, or an on-path attacker who drops packets.

## 1. Why a second file tool

`sahsync` (`~/development/systemapi.io/docs/sah-file-protocol.md`) copies and syncs through one WebSocket per session. Ops are sequential. Chunks are acknowledged. The agent hop credit window is 8 MiB. That is the right shape for many small paths and an audit row per change.

It is the wrong shape for one large file:

- TCP delivers a byte stream. One lost segment stalls every later byte until the retransmission arrives (head-of-line).
- The WebSocket, the TLS record, and the agent credit window each add a copy and a window on top of TCP.
- An ACK per chunk clocks the sender at the control-plane RTT, which includes SystemAPI, not just the path to the disk.

sahxfer keeps the SAH checks and moves the file on UDP. Each packet carries a file offset, so a loss repairs that range and no other. The receiver writes the range when it arrives. The temp file is the reassembly buffer.

UDP is not faster on every path. On a clean link the ceiling is the disk and ChaCha20-Poly1305. The win shows up when packets are lost or reordered, when the bandwidth-delay product is large, or when extra copies saturate a core. The spec still refuses to skip the cipher to chase a number.

## 2. Topology

```
 client                         SystemAPI                         host agent
   |  bearer, TLS 1.3               |                                  |
   |-- POST /api/v1/xfer/grant ---->|  intent audit, then push grant   |
   |                                |--------------------------------->|
   |<----------- grant -------------|                                  |
   |                                                                     |
   |   UDP sahxfer, or QUIC datagrams of the same sealed packet          |
   |<===================================================================>|
   |                                                                     |
   |                                |<-------- result -----------------|
```

The receiver reports the result, because only the receiver knows whether the rename happened. For `put` that is the agent, and the client does not report. For `get` (phase 2) the client is the receiver and reports through `POST /api/v1/xfer/<grant_id>/result`, accepted only from the grant's actor and recorded beside the agent's row, never replacing it.

The grant names the data-plane address. Three placements, one packet format:

| Placement | Who speaks UDP | When |
| --- | --- | --- |
| `direct` | Client and the host agent. | Policy says the host published a reachable UDP address. |
| `relay` | Both speak UDP to a relay. The relay forwards sealed packets. | Default. Agents are outbound and usually have no public UDP port. |
| `quic-bridge` | Client speaks QUIC to the bridge. The agent speaks UDP. The bridge copies one sealed datagram to the other side. | The client network allows QUIC and not high-rate UDP to an arbitrary port. |

The relay and the bridge see `transfer_id` and the route token. They do not see the grant key and they do not see plaintext. v1 has no mode where a middlebox decrypts the file.

A future hole-punch (both sides learn a reflexive address and try direct, with the relay as fallback) is out of v1.

## 3. Control plane

Auth matches the terminal and file protocols.

- Credential in a header only: `Authorization: Bearer` (device login) or `X-API-Key`.
- Never a query string. Never a UDP field.
- `GET /api/v1/hosts/resolve?name=` returns one host in the caller's tenants or an error. Substring search is not a resolver.
- TLS 1.3, system CA pool.

Login stays `sahconnect login`. sahxfer reads the same origin-bound token file. It does not write a second one.

### 3.1 Purposes

| Purpose | Scopes | Direction | Runs as |
| --- | --- | --- | --- |
| `xfer:put` | `file:read` + `file:write` | client sends the file | host `pty_user` |
| `xfer:get` | `file:read` | agent sends the file | host `pty_user` |
| `xfer:root` | `file:root` (admin) | put or get, selected by `dir` | root |

`xfer:put` and `xfer:get` are the v1 names. They reuse the file scopes so an operator who can write through `sahsync` can write through sahxfer, and no one else can. A new scope that meant the same thing would drift.

### 3.2 Grant request

```
POST /api/v1/xfer/grant
{"host_id":"<id>","purpose":"xfer:put"|"xfer:get"|"xfer:root",
 "dir":"put"|"get","root":"/srv/app","path":"releases/app.tar.gz",
 "size":123456789,"sha256":"<64 lowercase hex>","overwrite":false,
 "transport":"udp"|"quic-datagram"|"quic-stream"|"quic-bridge"}
```

`dir` is required for `xfer:root` and must match the purpose for the other two. A mismatch is `bad_purpose`.

`root` and `path` use the file protocol's rules (`sah-file-protocol.md` §2 and §5): absolute root, relative path, no `..`, no symlink resolution, component bounds, no Unicode normalization. The reserved component pattern gains `.sahxfer-*.part` beside `.sahsync-*.part`.

`size` is a byte count from 0 through `2^63-1`. A value that does not fit a signed 64-bit integer is `too_large`. Zero is an empty file: no `DATA`, only `FIN` and `DONE`.

`sha256` is the exact file contents. For `put`, the client has already hashed the local file. For `get`, the agent hashes the file before it sends, and the grant carries that hash back to the client. A `get` grant therefore waits until the agent has statted and hashed, and the grant is refused with `changed` if the file changes before the hash returns.

`transport` is a request. The server picks. The client cannot upgrade itself to `dc` pacing or to a decrypting path. Unknown transport is `bad_request`.

### 3.3 Grant response

Issued only after the intent audit row is durable. If that write fails, the response is `internal` and there is no grant.

```
{"grant_id":"xfr_<url-safe>","host_id":"<id>","transfer_id":"<16 hex chars, uint64>",
 "expires_at":"<iso8601>","expires_in":60,
 "idle_seconds":30,"max_seconds":3600,"byte_cap":<n>,
 "purpose":"xfer:put","root":"/srv/app","path":"releases/app.tar.gz",
 "size":123456789,"sha256":"...","overwrite":false,
 "profile":"internet"|"dc",
 "transport":"udp"|"quic-datagram"|"quic-stream"|"quic-bridge",
 "peer":{"udp":"203.0.113.10:4700","quic":null},
 "aead":"ChaCha20-Poly1305",
 "key":"<base64 of 32 bytes>","route_token":"<base64 of 16 bytes>"}
```

- `transfer_id` is 64 bits from the OS CSPRNG, checked unique among live grants, then stored. It is a demux id. It is not a secret.
- `key` is 32 bytes from the OS CSPRNG. `route_token` is 16 bytes from the OS CSPRNG.
- `expires_at` is the first-packet deadline: issue plus `expires_in` (60 s). It is not the end of the transfer. `idle_seconds` resets on any authentic packet. `max_seconds` is a hard stop from issue (default 3600). The client computes the hard stop as `expires_at - expires_in + max_seconds`, clamped to 3600 s after issue. A bootstrap file's `expires_at` has the same meaning.
- `byte_cap` is at least `size` and at most the tenant cap. Recommended tenant default for sahxfer is 256 GiB. `sahsync` stays at its own 16 GiB file cap. Policy may set a lower sahxfer cap. The protocol maximum is `2^63-1`.
- `profile` is chosen by the server. `internet` is the default. `dc` is allowed only when policy says both peers are on a tenant network.
- The same `key`, `route_token`, `transfer_id`, path, size, and hash are pushed to the agent on its existing authenticated channel. The push is not a new public port.
- `peer.udp` is always the address the client sends to. The server picks one of two peer modes and signs it into the lease (§3.4). `listen`: the helper binds an address the agent chooses, reports the bound or advertised address when it is ready, and the server returns that address as `peer.udp`. `dial:<host:port>`: the helper dials a relay and sends the first packet, and `peer.udp` is the relay. Behind NAT with no published port, `listen` cannot work; that is what the relay is for.

The client checks `host_id`, purpose, root, path, size, and hash against what it asked before it sends a packet. A mismatch is a local abort. The key is held in memory for the life of the grant and then wiped. It is not written to the token file. The HTTP client never writes a grant cache. The only disk copy is the explicit bootstrap file in §3.7.

Errors: `bad_purpose`, `bad_root`, `bad_path`, `scope_denied`, `root_denied`, `not_found`, `exists` (overwrite false and the target exists), `too_large`, `rate_limited`, `agent_offline`, `agent_unsupported`, `cap_reached`, `internal`. Same meanings as the file protocol where the names match.

### 3.4 What the agent does before it accepts packets

The agent refuses the push unless the lease verifies. The lease is the suite's `systemapi-lease-v1` envelope, signed as `"<action>\n<payload>"` with action `xfer` or `xfer_root`, with the control-plane Ed25519 key the agent already pins. The agent checks the envelope (key, host binding, action, expiry, skew, nonce replay). The helper does not; it receives a grant the agent has already verified. The payload is 18 lines joined by `\n`, no trailing newline. A builder refuses a control byte or a newline in any field.

```
 1 grant_id        ^xfr_[A-Za-z0-9_-]{8,64}$
 2 deadline_unix   lease deadline, issue plus 60
 3 start|renew
 4 put|get
 5 root            absolute
 6 path            relative, file protocol shape
 7 size            decimal
 8 sha256          64 lowercase hex
 9 overwrite       0 or 1
10 transfer_id     16 lowercase hex, not all zero
11 expires_unix    first-packet deadline
12 idle_s          1 to max_s
13 max_s           1 to 3600
14 byte_cap        decimal, at least size
15 profile         internet or dc
16 transport       udp in v1
17 peer            listen or dial:<host:port>
18 material        hex of sha256("sahxfer-material-v1\n" || key || route_token), raw 32 and 16 bytes
```

The payload binds every field the agent or the helper acts on, including a hash of the key material, so the server stores the material hash for renewals and not the key. The agent rebuilds the payload from the frame fields it is about to use, so a changed field fails as `payload_mismatch`. A renew is rebuilt from the stored grant with only the phase and the deadline changed, so a renew cannot change a field. A write lease does not authorize a get, and the reverse. Renewal is every 30 s. TTL is 60 s. If renewal fails, the helper aborts at the deadline it was given and deletes the temp file. `docs/golden-xfer-lease-v2.txt` is the shared test vector.

In v1 the UDP socket stays in the helper. The helper binds (`listen`) or dials (`dial:`) itself. A parent-owned socket that checks `transfer_id` and `route_token` and passes sealed datagrams to the helper is allowed by this design, but the agent already receives the key in the grant push, so moving the socket hides nothing; it is a later optimisation. A listening helper pins the first source address only after a datagram from it opens under AEAD, so a forged first datagram does not capture the transfer.

The helper is a child process with uid, gid, and groups dropped to `pty_user`, the same way the file helper does. `xfer:root` is a root helper and only on a root agent. Go must not drop privileges on one goroutine inside the agent process.

Path open, in the helper:

- Root: `openat2(AT_FDCWD, root, O_PATH|O_DIRECTORY, RESOLVE_NO_SYMLINKS)`.
- File: `openat2(rootfd, path, ..., RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS)`.
- No symlink is followed, inside or outside the root.
- A kernel without `openat2` is `agent_unsupported`. No fallback.
- Puts create `.sahxfer-<grant_id>.part` in the target's parent dirfd with `O_CREAT|O_EXCL|O_NOFOLLOW|O_RDWR`, mode 0600. The helper re-reads the temp file to fold the hash, so the descriptor is read-write. Mode stays 0600.
- Commit is `renameat2(RENAME_NOREPLACE)` when `overwrite` is false, otherwise `renameat` onto a regular file only.
- Gets open the regular file `O_RDONLY|O_NOFOLLOW` and refuse anything that is not a regular file, including a FIFO.

### 3.5 Audit

Content is not stored. Path, size, and sha256 identify the file.

- Intent row, before the grant response: actor, host, purpose, root, path, size, declared sha256, `grant_id`.
- Result row: `grant_id`, size, sha256, `bytes`, `status` (`ok`, `hash_mismatch`, `aborted`, `expired`, `io_error`), duration.
- A missing result means the grant ended without a commit. The target path must still be unchanged.

### 3.6 Completion

The receiver commits locally. It does not wait for a second control-plane RTT to rename.

1. Hole map empty, streamed SHA-256 equals the grant, `fsync` of the temp file, `fsync` of the parent directory, then rename (`RENAME_NOREPLACE` on Linux, `renameatx_np(RENAME_EXCL)` on Darwin, unless overwrite).
2. Send `DONE`.
3. The receiver reports the result to SystemAPI. For `put` that is the agent, with `committed` true once the rename happened, even if `CLOSE_ACK` never arrives. The client does not report a put. For `get` (phase 2) the client reports (§2).

`DONE` before `fsync` is forbidden. A crash before rename leaves the target unchanged. The temp file is removed on abort, expiry, and process exit.

The optional grant flag `integrity=reread` (server policy, not a client choice) re-hashes the temp file from disk after `fsync` and before rename. The default is the streaming hash. AEAD already binds the bytes the helper accepted. The re-read catches a disk that did not store those bytes. It costs a full extra read.

### 3.7 Local grant file (bootstrap only)

SystemAPI does not issue this grant yet. `sahxfer grant` can write a one-shot file so two local processes can run the data plane. The file holds the key and the route token. Create it mode `0600`, open it `O_NOFOLLOW`, and refuse it if it is not a regular file owned by the user or if group or other permission bits are set. This is not a cache and not the sahconnect token file. The operator opts in by passing the path. A grant that arrived over HTTPS stays in memory until `Wipe` and is never written here.

## 4. Wire format

One UDP datagram is one frame. There is no segmentation below the datagram and no stream across datagrams. A frame that does not fit one datagram is not sent.

First four bytes, in order: `0x53 0x41 0x48 0x58` (`SAHX`). Every integer after that is little-endian. Multi-byte integers are 64-bit except the version, type, and flags in the first eight bytes.

```
offset  size  field
0       4     magic
4       1     version = 1
5       1     type
6       2     flags
8       8     transfer_id
16      8     seq                  // per direction, starts at 1
24      8     offset               // meaning depends on type
32      8     payload_len          // plaintext length
40      8     send_time_ns         // sender monotonic clock, arbitrary epoch
48      8     route_token[0:8]
56      8     route_token[8:16]
64      N     ciphertext           // N = payload_len
64+N    16    Poly1305 tag
```

The header is 64 bytes. `route_token` is the 16-byte secret split across two `u64` slots so the header stays 64-bit aligned. Datagram length must equal `80 + payload_len`. Anything else is dropped.

`seq` 0 is unused. A peer never reuses a seq under the same key and direction. Grants are far below `2^64` packets, so the sequence does not wrap. A wrap aborts the grant.

### 4.1 AEAD

ChaCha20-Poly1305 as in RFC 8439. The 64-byte header is associated data. The plaintext is the payload. The tag is the last 16 bytes.

Nonce, 12 bytes, little-endian:

```
byte 0        direction   0 = client, 1 = agent
bytes 1..3    0
bytes 4..11   seq
```

Each direction has its own sequence space. A client packet and an agent packet with the same seq do not share a nonce.

The library open checks the tag in constant time. On failure the packet is dropped. It is not NACKed. It is not answered. After 32 failed opens on one grant, the helper aborts with `auth` and tells the control plane. The parent applies the same budget to route-token mismatches so a guesser cannot move the failure into the helper to see a timing difference.

No other cipher in v1. No negotiation. No `crypto=off`.

### 4.2 Types

| Type | Code | Payload |
| --- | --- | --- |
| `DATA` | 1 | File bytes. `offset` is the file position. |
| `NACK` | 2 | Hole list. `offset` is the highest contiguous byte (the receiver holds `[0, offset)`). |
| `FEEDBACK` | 3 | Congestion sample. Not a repair request. |
| `FIN` | 4 | Empty. `offset` is the file size. Sender has put every byte on the wire at least once. |
| `DONE` | 5 | 32-byte SHA-256. `offset` is the file size. Sent only after fsync and rename. |
| `ABORT` | 6 | One `u64` reason. |
| `PING` | 7 | Empty. `offset` is the probe id. Bit 62 of a receiver's probe id is `ZERO_OK` (§4.7). |
| `PONG` | 8 | `u64 echo_send_time_ns`, `u64 receiver_delay_ns`. `offset` echoes the probe id. |
| `ZERO` | 9 | One `u64 length`. `offset` is the file position. The span is all zero bytes (§4.7). |

Unknown type on an authentic packet aborts with `protocol`. A packet that fails AEAD is dropped with no abort. A receiver that did not set `ZERO_OK` treats `ZERO` as unknown.

Flags:

| Bit | Name | Where it is legal |
| --- | --- | --- |
| 0 | `RETX` | `DATA` and `ZERO`. This range is a retransmission. |
| 1 | `CLOSE_ACK` | `FIN` only, and only after the sender has accepted a valid `DONE`. |

Any other bit, or a bit set on a type where it is not legal, aborts with `protocol` after the packet opens. A later feature is a version bump, not a new quiet bit.

A version other than 1 is dropped before AEAD. The receiver does not abort the grant, and it does not write.

`payload_len` caps:

| Profile | Max datagram | Max plaintext |
| --- | --- | --- |
| `internet` | 1280 − 40 − 8 = 1232 (IPv6 minimum, minus IPv6 and UDP headers) | 1152 |
| `dc` | 8192 | 8112 |

Path MTU discovery may raise the internet cap up to 2048 bytes of datagram and no further in v1. It may not raise the cap above the profile the grant issued. Probing uses `PING` padded with zero plaintext, still AEAD'd. A lost probe lowers the cap. A cap is never raised during the `FLUSHING` state. The first implementation does not probe. The plaintext cap stays at the profile default: 1152 on `internet`, 8112 on `dc`.

`offset + payload_len` is computed with a checked add. Wrap, or a span past `size`, aborts with `protocol` when the packet is authentic. `DATA` length 0 is `protocol` unless `size` is 0, in which case there is no `DATA` at all.

### 4.3 NACK payload

```
u64 hole_count
hole_count times:
    u64 start     // inclusive file offset
    u64 end       // exclusive
```

`hole_count` is 0 through 32. Holes are ordered, non-overlapping, and each `start < end <= size`. The list names the oldest mature holes that fit. More holes travel in the next NACK. A NACK or `FEEDBACK` whose `offset` (the receiver's contiguous prefix) is above the bytes the sender has sent once aborts with `protocol`: no honest receiver holds a contiguous byte that never left, and the sender's delivery count for the controller starts from that offset (§4.7), so it must not exceed what was sent.

A hole is mature when a byte past its end has been accepted, or when it is older than `max(3 * srtt, 1 ms)` and any later seq has been accepted. The trailing edge, where later bytes simply have not arrived, is not a hole. `FIN` plus a timer covers that tail.

The receiver sends a NACK at least once per smoothed RTT while any mature hole exists, and immediately when a hole becomes mature. NACKs are idempotent. Loss of a NACK is repaired by the next one.

### 4.4 FEEDBACK payload

Fixed 48 bytes:

```
u64 echo_send_time_ns     // send_time_ns of the highest-sequence DATA ever accepted; 0 if no DATA was accepted since the previous FEEDBACK
u64 delivered_bytes       // unique file bytes accepted
u64 newly_lost_bytes      // bytes newly named by mature holes since the previous FEEDBACK
u64 highest_seq_received  // seq of the newest DATA that added bytes; a duplicate does not raise it
u64 ecn_ce_count          // 0 if the socket has no ECN
u64 recv_rate_bps
```

`offset` in the header is the highest contiguous file byte, the same value as on a NACK.

Cadence: every `max(5 ms, srtt / 4)`, and at least every 64 accepted `DATA` packets. FEEDBACK does not request a retransmission. The sender retransmits only on NACK, plus the stall probe (below).

### 4.5 Close

Pure NACK cannot finish a transfer. A receiver with a complete file and a lost final NACK would wait forever, and a sender that stops early would look the same as a sender that is done. `FIN` and `DONE` are the two positive close signals. They are not per-packet ACKs.

- Sender, after every byte has been transmitted once: state `FLUSHING`, send `FIN` every RTT.
- Receiver, after commit: send `DONE` every RTT until a `FIN` arrives with `CLOSE_ACK` set, or until `idle_seconds`.

Stall probe. It applies in `SENDING` and `FLUSHING`, while sent segments above the contiguous offset are in flight and nothing is queued for repair. Progress is an advance of the contiguous offset or of `FEEDBACK` `delivered_bytes`. The stall clock starts at the later of the last progress and the send time of the oldest segment still in flight, so a segment is never judged before it could have been answered. `W = 2 * max(srtt + 4 * rttvar, 5 ms)`, and 1 s before the first RTT sample. `rttvar` follows RFC 6298: the first sample `R` sets `srtt = R` and `rttvar = R / 2`; each later sample sets `rttvar = 3/4 * rttvar + 1/4 * |srtt - R|`, then `srtt = 7/8 * srtt + 1/8 * R`.

1. Tail probe. After `W` without progress, the sender retransmits its highest in-flight segment once, with `RETX`, as TCP's tail loss probe does. It releases nothing and is not a loss signal. If it arrives, the receiver holds a byte past every lost range, each of those ranges becomes a mature hole, and NACK repair, which is a loss signal, takes over. On a path whose RTT has just grown, it costs one segment.
2. Range probe. If the tail probe is followed by no progress for `max(2 * W, 1 s)`, the sender treats everything outstanding as lost, as TCP treats a retransmission timeout. Each in-flight segment sent longer ago than the repair timeout (section 6) leaves the in-flight count, its range is queued for retransmission with `RETX`, and its bytes count as newly lost. A segment leaves the in-flight count only when its range is actually queued. A range refused because a younger send overlaps it stays in flight, and the sender wakes to retry when that send ages out. Each further range probe without progress doubles the wait, up to 8 s. Progress returns the next stall to the tail probe.
3. Undo (F-RTO/Eifel style). A range probe may be spurious: when only the reverse path failed, the receiver has every byte and only its `FEEDBACK` was lost. The sender records the probe: the bytes it counted as lost, the ranges it released, the next sequence number it will seal (`undo_seq`), and the controller's loss state just before the probe. Until the first `FEEDBACK` after the probe arrives, the sender sends no new `DATA`, only the queued repairs, so that a `DATA` sealed after the probe can only be a repair. On each `FEEDBACK` while the record is open, before the controller takes its sample:
   - If `highest_seq_received < undo_seq` and the contiguous offset is at or past the end of every released range, the receiver holds every released byte and none of them came from a repair. The probe was spurious. The loss it counted is removed from the controller, a loss round it caused is reverted (`inflight_lo` and `bw_lo` are restored, and STARTUP is restored only if a reverted loss round is what ended it), and repairs still queued for those ranges are dropped. The record closes.
   - If `highest_seq_received >= undo_seq`, a repair added bytes: the loss was real, and the record closes.
   - If `highest_seq_received` is 0, or lower than a value this receiver already reported, the receiver does not follow the rule in section 4.4, and the record closes with the loss kept. A non-conforming receiver cannot make the sender forget a loss.
   - Otherwise the record stays open.
   The first `FEEDBACK` after the probe also ends the hold on new `DATA`. A later range probe replaces an open record. The decision uses only fields already on `FEEDBACK`. A reverse-path outage of 1.5 to 3 s with no `DATA` lost was counted as 324 lost segments, cut once, and resent all 324 before this rule.

Why. A NACK can name only a hole below the highest byte the receiver holds, so when a burst swallows every `DATA` above `contig` there is no hole to name: without a probe the in-flight count never frees, the cap holds back new `DATA`, and the receiver aborts with `idle`. In `FLUSHING` the probe also covers a lost final segment, which the receiver cannot NACK either. An RTT step-up after a route change also stops `FEEDBACK`, for one new RTT, which any wait computed on the old RTT underestimates. A first version resent the whole window after `2 * max(srtt, 5 ms)`. On a clean 5 MB/s path that cost 50% more time when the delay went from 10 to 100 ms each way, and a 50 to 250 ms step ran past a 300 s grant. The tail probe costs one segment in that case. The range probe waits at least 1 s, RFC 6298's minimum RTO. The 5 ms floor in `W` is there because progress arrives only with `FEEDBACK`, at most every 5 ms; a shorter wait would probe between two `FEEDBACK`s of a healthy transfer. The sender keeps sending `FIN` in `FLUSHING`. Give-up is the grant `max_seconds` or `idle_seconds`, then `ABORT` with `expired` or `idle`.

### 4.6 ABORT reasons

| Code | Name |
| --- | --- |
| 1 | `size_mismatch` |
| 2 | `hash_mismatch` |
| 3 | `expired` |
| 4 | `policy` |
| 5 | `io` |
| 6 | `protocol` |
| 7 | `auth` |
| 8 | `cancelled` |
| 9 | `byte_cap` |
| 10 | `idle` |
| 11 | `no_space` |

`ABORT` is sent best-effort, then the grant is dead. The helper deletes the temp file. A late `DATA` for a dead grant is dropped.

### 4.7 ZERO (zero-run skipping)

Disk images, VM disks, and preallocated databases carry long runs of zero bytes. Measured on this tree's build host (2026-10-18, scratch `zero/scan.txt`): an 8.6 GB raw Linux image is 90.6% zero in 1152-byte blocks (89.5% of it a sparse hole, plus 10.5% of the allocated extents), a 64 GB Docker Desktop VM disk is 31.4% zero (holes plus 14.1% of a 4 GB sample of its extents), and an ISO, a Go binary, and a source tar are 0.0 to 1.5%. Comparing a 1152-byte block with zero costs 19 ns when it is zero (0.016 ns per byte) and 4 ns when the first word is not, against about 25 ms per MB the pipeline spends now. General compression is a v2 protocol (`docs/compression-study-2026-10-18.md`) because it moves bytes off file offsets. A zero run does not: its offset and length name the bytes exactly, so `ZERO` keeps every offset a file offset, keeps NACK and the hole map as they are, and keeps SHA-256 over the whole file.

Frame. `ZERO` is type 9. `offset` is the file position. The payload is 8 bytes, `u64 length`, sealed like any payload. `[offset, offset+length)` is all zero bytes. It shares the `DATA` sequence space and nonce rule, may carry `RETX`, and a forged one fails AEAD like a forged `DATA`.

Negotiation. A receiver that accepts `ZERO` sets bit 62 (`ZERO_OK`) in the `offset` of every `PING` it sends. The sender sends `ZERO` only after an authentic `PING` with that bit. Until then, and with a receiver that never sets it, zero bytes go as `DATA`. Smallest change that a v1 peer cannot trip on:
- A header flag on `PING` would abort a v1 sender (`protocol` on a flag on the wrong type).
- Version 2 is dropped before AEAD by a v1 peer and a v1 relay, so it degrades safely, but it needs the seal, the relay, and a second header path.
- A grant field changes the 18-line lease payload and its golden vector, which the server and the agent share byte for byte: three repositories.
- The probe id is opaque to a v1 peer. A v1 sender echoes it in `PONG` and does not read it. A v1 receiver counts probe ids up from 1, so it never sets bit 62. Neither old peer sees a change, and the datagram version stays 1. The bit travels inside AEAD; only the peer that holds the grant key can claim it, and a receiver that claims it and then mishandles `ZERO` only fails its own transfer's hash.

Detection, on the sender, for new bytes. With `ZERO_OK`, each block of `MSS` bytes at a multiple of `MSS` is compared with zero before it is sealed. The last block of the file may be shorter than `MSS`. A zero block starts a run; the sender reads on, block by block, while each block is zero, up to `floor(1 MiB / MSS) * MSS` bytes or the end of the file, and sends the run as one `ZERO`. A run of at least `MSS` bytes is a `ZERO`. A file's short final block alone is not: it goes as `DATA`, so a `ZERO` is never shorter than one `DATA` would have been, except the file's tail joined to a run. A run longer than the cap is several `ZERO`s, each starting at a multiple of `MSS`. A non-zero block goes as `DATA` from the buffer it was read into, so a file with no zeros costs one compare per block and no extra read.

Repair. A NACK hole or a stall probe inside a zero run is a range like any other. The repair reads the range again; a zero prefix of at least `MSS` bytes, or a range that is zero to its end, goes as `ZERO`, otherwise `DATA` of up to `MSS`. Either frame carries the same bytes at the same offset, so the one-plaintext rule (§5) holds whichever the sender picks. A range first sent as `DATA` and repaired as `ZERO` is counted for the controller as the `DATA` bytes it was first sent as, which over-counts the wire by at most that range less 88 bytes. It happens only to zero bytes sent before `ZERO_OK` arrived (about one RTT of data at the start) or to a zero tail of a repaired range, and each such range is counted once; the bandwidth sample it inflates is at most one round's.

Charge. Pacing, the in-flight cap, and loss are about wire bytes; delivery, the hole map, and `byte_cap` are about file bytes.
- In flight and pacing: a `ZERO` is charged 88 bytes, its whole datagram (`DATA` stays charged its payload). `CanSend`, `OnSend`, the in-flight count, and the bytes released when it is filled or presumed lost use 88.
- Loss: a lost `ZERO`, from a NACK or a range probe, counts 88 bytes. A NACK hole that overlaps a `ZERO` only in part (a hole split by a partial repair) is charged the overlap less the `ZERO`'s length beyond 88 bytes, so it too counts at most 88. Counting its length would turn one dropped 88-byte datagram into a 1 MiB loss and, with several, a cut.
- Bandwidth: `FEEDBACK` `delivered_bytes` counts a `ZERO` as `length` file bytes, as the receiver holds them. The sender clamps it to the bytes it has sent once (§6), giving `d`, and feeds the controller `(contig - Zb) + max(0, d - contig - Za)`. `Zb` is `length - 88` summed over the `ZERO`s sealed for the first time that lie wholly below `contig`; `Za` is the same over the rest. Below `contig` the count is exact. Above it, every `ZERO` not yet below `contig` is taken off whether or not it landed, so the count can fall short there and never exceeds the wire bytes delivered. A first version subtracted every `ZERO` sent from `d`: while a `ZERO` was in flight the count dipped under its previous maximum, the `DATA` delivered meanwhile was credited in one round when the `ZERO` landed, and on a 5 MB/s simulated link with 4 MiB zero runs the estimate reached 14 MB/s with 274 tail drops. Without any adjustment it reached 214 MB/s with 6218 drops. The rule above keeps it at 4.7 MB/s with none. A peer that reports more than the file is clamped first, so it cannot raise the estimate either.
- `byte_cap`: unchanged in meaning. The sender adds a `ZERO`'s `length` when it seals it for the first time; the receiver's unique accepted bytes include it. A grant's cap is at least `size`, so an honest transfer cannot trip it, and a `ZERO` cannot be used to move more than the cap. The relay charges `DATA` payload only; it cannot read a `ZERO`'s length, and like the other control frames a `ZERO` costs it 88 bytes uncharged.

Receiver, after the packet opens:
- Refused with `protocol`: a payload other than 8 bytes, `length` 0, `length` above 1 MiB, `offset + length` wrapping or past `size`, `size` 0, or a receiver that did not set `ZERO_OK`. The 1 MiB bound caps the work one datagram can ask for (each side hashes a `ZERO`'s bytes); the size bound keeps a `ZERO` inside the grant like a `DATA`.
- For each range of the span that the hole map still lacks: extend the temp file to the range end with `ftruncate` if it is shorter (never shrink it), then deallocate the block-aligned inside of the range with `fallocate(FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE)` on Linux or `fcntl(F_PUNCHHOLE)` on Darwin. A filesystem that does not support the punch is not an error. A range the hole map lacks was never written (first write wins, and the write happens before the accept), so it already reads as zero once the file covers it: the punch is a no-op on a filesystem that left it sparse and frees blocks on one that allocated them on extend. An extend that fails is `io`. A file without those calls (the in-process tests) writes one zero byte at the end of the range, which extends the file and reads the same.
- Then the span is accepted into the hole map, counted toward `delivered_bytes`, raises `highest_seq_received` when it added bytes, and counts toward the 64-packet `FEEDBACK` trigger, exactly as `DATA` of `length` bytes.
- The streaming hash folds the contiguous prefix by reading it back from the temp file, zero ranges included, in chunks of at most 1 MiB. A received packet and a `Pump` each fold at most 64 KiB, and while the hash lags the next `Pump` is due 1 µs later, so the `FEEDBACK` and NACK timers still run; after `FIN`, with the hole map empty, each `Pump` folds 1 MiB until the hash reaches `size`, and `FEEDBACK` keeps flowing, so neither peer goes idle while a large sparse tail is hashed. Measured: a 2 GB file, 88% zero, over loopback with `idle_seconds` 8 committed in 29.5 s; in process the hash lagged the contiguous prefix by at most 253 MB, about 0.8 s at the 329 MB/s Go SHA-256 does on the build host, hashed in 3 ms steps between which `FEEDBACK` goes out. The lag is bounded by `size` only in principle (an all-zero file arriving faster than it hashes); the receiver must hash every byte either way, so `max_seconds`, not `idle_seconds`, is the limit that applies. So a run of `ZERO`s neither allocates its length nor holds the receive loop on SHA-256, and a hash that lags does not slow every `DATA` behind it. The sender seals at most one `ZERO` per `Pump`, and none while another datagram sealed in that `Pump` (a `PONG`, a `FIN`, a `DATA`) waits: it checks before it scans past the first zero block, so a `PONG` never waits behind a cold 1 MiB read. A first version allowed 16 MiB per `ZERO` and hashed a whole contiguous run at once: each side then spent about 40 ms per `ZERO` on SHA-256 without reading its socket, the receive buffer overflowed, and a 300 MB, 50%-zero loopback transfer took 135 s instead of 4. The hash, `DONE`, the `FIN` size check, and the commit order are unchanged. A sender cannot skip the hash: the receiver hashes the bytes the file now holds, and a `ZERO` over a range that is not zero in the source fails `hash_mismatch`.
- Idle and the agent events: an authentic `ZERO` resets the idle timer like any authentic packet; the `active` and `result` byte counts are file bytes and include zero runs. v1 has no resume (§12); when it lands, its prefix hash is over file bytes, so a zero run resumes like any other range.

Measured on the same host, one core each side:
- Loopback UDP, 300 MB with 51% zero in runs of 64 KiB to 64 MiB, two runs each, quiet host: 6.6 and 7.8 s with 329 to 331 MB on `lo0` before; 4.2 to 5.2 s with 158 to 160 MB after. Busier host, final build: 9.8 and 10.5 s before, 8.4 and 8.5 s after, 158 MB against 330 MB on the wire. The target holds 159 MB of blocks against 302 MB before. A 300 MB random file is unchanged within the run-to-run spread.
- In process (`TestZeroLargeSparseFile`, a 100 MB/s, 1 ms simulated link), 200 MiB at 54% zero: 1.07 s and 104 MB on the wire with 109 `ZERO`s, against 2.28 s and 224 MB for the same file sent as `DATA` and for a random file.
- Linux (golang:1.27 container on the same host, loopback): 30 MB at 52% zero took 0.79 s in one run and 8.9 s in another; the container's bimodal rate (§7.4) dominates there.

Threats: a forged `ZERO` fails AEAD. A `ZERO` past the grant size, wrapping, empty, or above 1 MiB aborts with `protocol`. A `ZERO` sent to a receiver that did not ask for it aborts with `protocol`. A lying `delivered_bytes` is clamped to the bytes sent once before `Z` is subtracted. A `ZERO` over non-zero source bytes is a hash mismatch, not a silent corruption. Not defended: a receiver on a filesystem without sparse files stores the zeros in full, which is what `DATA` would have cost.

## 5. Reliability

The sender keeps the file. It does not keep a second copy of packets it can rebuild from disk plus the cipher. A retransmission reads that range again, seals it under a new seq, and sets `RETX`. The plaintext at a given offset is fixed for the life of the grant. The sender must not seal two different plaintexts at the same offset.

The receiver, after a successful open:

- If `[offset, offset+len)` is already filled, drop the plaintext. First write wins. A `ZERO` is the same with its `length` and no plaintext: the missing ranges are made to read as zero (§4.7). Do not read the file back to compare. Replay of the same bytes is a no-op. A sender that violates the one-plaintext rule is a broken sender; the receiver will hash-mismatch and abort.
- Otherwise `pwrite` the plaintext at `offset` (or the io_uring equivalent) and mark the range filled.
- Update the streaming SHA-256 only for bytes that just became part of the contiguous prefix. Out-of-order ranges sit in the file and in the hole map until the gap in front of them closes, then they fold into the hash in order.

The hole map starts as `[0, size)` and is an interval set of missing ranges. It is metadata. It does not hold file bytes.

Reorder is normal. A gap is not loss until it is mature (§4.3). Spurious retransmission is harmless because of first-write-wins.

`byte_cap` counts unique file bytes the sender has sealed for the first time, plus unique bytes the receiver has accepted, a `ZERO` by its `length` (§4.7). A retransmission does not add to the cap. Exceeding the cap aborts with `byte_cap`.

Empty file: sender sends `PING`, waits for one `PONG`, sends `FIN` with `offset=0`. Receiver commits a 0-byte temp file, renames, sends `DONE` with the SHA-256 of the empty input (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).

## 6. Congestion

NACK repair is not a congestion signal by itself, and there is no ACK clock. v1 congestion control is paced and rate-based. The controller is **pace-bbr**. It follows the shape of BBRv3 (draft-ietf-ccwg-bbr) and uses `FEEDBACK` as the aggregated acknowledgement. It is not a byte-identical implementation of that draft. Code and docs call it pace-bbr.

Signals the sender must use:

- Bandwidth, from `delivered_bytes`. The sender ignores a `delivered_bytes` that is not greater than the largest it has used, so a reordered `FEEDBACK` does not move the count back and let the next sample count the same bytes twice. It clamps the value to the unique file bytes it has sent, so an authenticated peer that reports more cannot raise the estimate past what left the sender. It then subtracts the bytes `ZERO` frames represent beyond their 88-byte datagram (§4.7), so a zero run is measured as the wire bytes it took.
- RTT, from `PING`/`PONG` (`send_time` echoed, plus `receiver_delay_ns`) and from `echo_send_time_ns` on `FEEDBACK`. The `FEEDBACK` echo is the `send_time_ns` of the highest-sequence `DATA` ever accepted, sent only when some `DATA` was accepted since the previous `FEEDBACK`, and 0 otherwise (section 4.4). The sender takes an RTT sample only from an echo greater than the last echo it sampled. A repeated echo is not a sample: after the last `DATA`, a timer `FEEDBACK` that repeated the same old send time every 5 ms would grow `srtt` by 5 ms each time, the `FIN` retry would back off with it, and a burst of lost `FIN`s would end in `idle`. The `DATA` behind a fresh echo, one greater than any echo before it, arrived after the previous `FEEDBACK`, so the sample also holds the time it waited for this one: at most one FEEDBACK interval (`max(5 ms, srtt / 4)`) plus the receiver's scheduling delay, and close to 0 when the 64-`DATA` trigger sent it. The pacer's min-RTT filter discards that hold. The sender's `srtt` keeps it, so its `FIN`, stall-probe, and repair timers allow for one FEEDBACK interval. A `PONG` whose echoed send time is earlier than the moment this peer accepted its first authentic packet is not an RTT sample, on either peer: that `PING` may have waited in a listener's pre-pin queue or in the relay's 1 s hold (section 8), and the delay would become `srtt`. Each peer sends one fresh `PING` when it first hears the other, so a dropped sample is replaced one RTT later.
- Loss, from NACKs. The repair timeout is `2 * srtt`. The newly lost bytes of a NACK are the bytes in its holes that are neither queued for repair nor covered by a retransmission sent within the repair timeout. A retransmission older than the repair timeout inside a NACKed hole is presumed lost: it leaves the in-flight count, its range is sent again, and its bytes count as newly lost again. The timeout is `2 * srtt`, not `srtt`, because a NACK shows the receiver as it was a one-way delay earlier and queueing can hold a repair past `srtt`; with `srtt`, a 1% loss simulation counted 90 losses for 86 drops and sent the 4 extra repairs. A re-NACK of a hole whose repair is still in flight adds nothing, so the receiver repeating its hole list every RTT is not repeated loss. `newly_lost_bytes` on `FEEDBACK` is not used by the controller: it names the same holes the NACK names, and using both would count one loss twice. An `ecn_ce_count` increase counts one MSS of loss per new mark. A range probe (section 4.5) counts the bytes it releases as newly lost, the strongest loss signal, as a TCP retransmission timeout is, unless the undo rule in section 4.5 finds it spurious and removes that loss again; its queued ranges then cover later NACKs of the same bytes, so they are not counted twice. The tail probe is not a loss signal: it is sent on silence, which an RTT step-up also causes.
- Application-limited, once the sender has no new file bytes and is only retransmitting.

pace-bbr behavior:

- Startup pacing gain is 2.89 until a loss round (below) or until a round's bandwidth fails to grow by 25% for three rounds, then DRAIN.
- DRAIN pacing gain is 0.35 until inflight is at most the bandwidth-delay product.
- PROBE_BW cycles pacing gains `[1.25, 0.75, 1, 1, 1, 1, 1, 1]`, holding each for one round length `L` (below), measured on the sender's clock.
- PROBE_RTT holds the window at `4 * MSS` for `max(200 ms, RTprop)` when the minimum RTT sample is about 10 s old. When PROBE_RTT ends, RTprop becomes the least RTT sample taken during it, but not more than the controller's smoothed RTT (an EWMA of the same samples, 1/8 gain), and unchanged if no sample was taken; its age restarts. The cap keeps one probe whose few samples were all outliers, a burst of delayed `FEEDBACK` for instance, from raising RTprop past what the path has been showing; a real step-up still lands within one or two probes, because the smoothed RTT has followed it for the 10 s before. RTprop can therefore rise. Without that, a route change from 50 to 250 ms each way left the cap and the rounds sized for a 100 ms RTT against a 500 ms one: the cap let through 40% of the estimated rate, the windowed bandwidth max decayed round after round to the `10 * MSS` floor, and 10 MB on a clean 5 MB/s path took 114 s.
- Loss rounds. Newly lost bytes accumulate per round. When a round ends, the loss rate is `lost / (delivered + lost)` summed over the last 4 rounds. A round that ends with that rate above 2%, BBRv2/v3's loss threshold, is a loss round. The rate is judged only over a full window: 4 rounds since the first round or since the previous loss round, which also empties the window. In STARTUP a loss round also needs at least 6 segments lost in the window (BBRv3's `full_loss_cnt`): early drops in a flight of a few segments are a high rate but not a full pipe. One round of 1% loss on a 174-segment round is 1.7 drops on average and exceeds 2% about one round in ten, so a single-round rate would cut every few hundred milliseconds; over 4 rounds a steady 1% exceeds 2% about 1% of the time. At most loss rate 2%, loss is repaired and does not change the model: random loss is not congestion, and cutting on every round with one drop ratcheted a 5 MB/s, 20 ms each-way path down to 0.69 MB/s at 1% loss and 0.13 MB/s at 5%. At the end of a loss round, leave startup for drain, and set `inflight_lo = max(BDP, inflight * 0.85, MSS)` and `bw_lo = max(latest, 0.85 * bw_lo)`, where `latest` is the bandwidth sample of the round just ended (0 if it took none) and an unset `bw_lo` counts as `bw_max`. A round is a loss round at most once. `inflight_lo` and `bw_lo` hold until PROBE_BW next begins its 1.25 phase by completing a cycle; entering PROBE_BW from DRAIN or PROBE_RTT does not clear them. While set, the pacing rate and the cap use `bw = min(bw_max, bw_lo)`, and the cap is also at most `inflight_lo`. This is the BBRv2/v3 short-term model, simplified. Do not run Reno or CUBIC beside this controller.
- The round length is `L = max(RTprop, 5 ms)`, and 5 ms before the first RTT sample. Rounds are delimited by `FEEDBACK` arrivals, not by a timer. The first `FEEDBACK` that changes `delivered_bytes` starts the first round. A round ends at the first `FEEDBACK` that arrives at least `L` after the round began, and that arrival starts the next round. The bandwidth sample for the round is the change in `delivered_bytes` between the two arrivals divided by the time between them, both measured at the sender when the `FEEDBACK` is processed. Both ends are `FEEDBACK` arrivals, so the bytes and the time cover the same span: a timer round of 5 ms against a 5 ms `FEEDBACK` sometimes held two `FEEDBACK`s and doubled the sample under small jitter. `L` is never shorter than the receiver's cadence floor, because `FEEDBACK` is the only delivery signal. A round with no new delivery takes no sample, so a stall while a hole waits for repair does not age the estimate toward 0. An application-limited round takes no sample.
- `bw_max` is the maximum of the last 10 samples. The window shifts only on a round that takes a sample, so a round without one does not age the estimate. A high sample ages out after 10 sampled rounds instead of holding for the grant.
- The inflight cap is `max(2 * bw * L, 10 * MSS)`, then at most `inflight_lo` when that is set. PROBE_RTT replaces it with `4 * MSS`. Before a bandwidth sample it is `10 * MSS`. New data leaves only while inflight plus the segment fits the cap. A retransmission is paced but not held by the cap, so inflight can exceed the cap by the bytes under repair. Bytes above a hole count in flight until the hole fills, and `inflight_lo` is set below inflight at the moment of loss, so a cap on repairs could block the only send that frees them; with a persistent `inflight_lo` that is a deadlock. Repairs are bounded by the NACK (at most 32 holes), the sender's suppression of a range sent within the repair timeout (`2 * srtt`), and the pacing rate. Every data transmit, including a retransmission, is paced.
- Each send is scheduled `n / (gain * bw)` after the previous send's scheduled time, not after the moment it actually left. If the previous scheduled time is more than 1 ms behind the clock, the sender was idle rather than late, and the next send is scheduled from the clock with no credit. A runner wakes late, and scheduling from the actual send time loses that lateness on every packet: the measured rate then falls below the pacing rate, and with a windowed max the estimate ratchets down round after round (30 MB on loopback fell from about 3 s to about 12 s). The 1 ms bound limits a catch-up burst to about 1 ms of data at the pacing rate plus one segment, and a sender coming back from idle sends one segment, then paces. The catch-up is not capped at a segment count: at 100 MB/s, 1 ms is about 87 segments, and a smaller cap would bring back the rate loss above at exactly the rates where a late wake-up costs the most.
- Why that cap. Only `FEEDBACK` frees in-flight bytes, and the receiver sends it every `max(5 ms, srtt / 4)` or after 64 accepted `DATA` (section 4.4). A byte sent at `t` is freed no earlier than `t + RTprop + hold`, where the hold is up to one FEEDBACK interval. On a path whose RTprop is under 5 ms, a cap of `bw * RTprop` limits the transfer to one cap per 5 ms: 10 MSS of 1152 bytes per 5 ms is about 2.3 MB/s on loopback whatever the link can do. `max(RTprop, 5 ms)` is BBR's allowance for aggregated acknowledgements, with the receiver's cadence floor as the aggregation time. `srtt / 4` exceeds RTprop only when the queue already holds three base RTTs, which this controller does not aim for, so the floor is the 5 ms constant and not the receiver's `srtt`. The factor 2 is BBR's cwnd gain. Without it the cap equals what the measured bandwidth covers and the measured bandwidth equals what the cap lets through, so startup cannot grow. Since `2 * max(a, b) >= a + b`, the cap covers one RTprop plus one FEEDBACK interval at the estimated rate. The pacing gain, not the cap, sets the send rate. The receiver's cadence and the wire format are unchanged.
- A `RETX` byte counts in flight until the matching range is filled or the grant ends.
- ECN is used when the socket reports it. `ecn_ce_count` is the loss signal. A path with no ECN sends zeros.
- `profile=dc` may use the `dc` plaintext cap. It does not get a different congestion algorithm.
- The client does not choose the algorithm.

Before the first `DATA`, the sender sends three `PING`s, `10 ms` apart, or fewer if a `PONG` arrives and `srtt` is already under `10 ms`. It may start `DATA` after the first `PONG`, even when that `PONG` is not an RTT sample under the rule above. If no `PONG` arrives within `1 s`, it sends one more `PING` and then aborts with `idle` at `idle_seconds`.

When the transport is `quic-datagram` or `quic-bridge`, this controller is off. QUIC's controller is the only one. The sender still NACKs. Turning both on is a bug.

## 7. I/O path

The cipher has to touch every byte. "Zero copy" here means no extra copies around that touch.

### 7.1 Sender (the peer that has the file)

1. Open the file read-only.
2. Register a fixed buffer ring (Linux io_uring). Fill a buffer with `READ_FIXED` at the file offset.
3. Seal ChaCha20-Poly1305 in that buffer, writing ciphertext over the plaintext or into the datagram slot of the same registration.
4. `SEND_ZC` (or `sendmmsg` where zero-copy send is unavailable). Recycle the buffer only after the send completes.
5. A retransmission repeats steps 2–4 for that offset under a new seq.

The page cache is the source of the read. v1 does not use `O_DIRECT` and does not `mmap` the file. `mmap` faults at a time the pacer does not control.

### 7.2 Receiver

1. `recvmmsg` or a multishot io_uring recv into a registered buffer.
2. AEAD open in that buffer.
3. `WRITE_FIXED` / `pwrite` at `offset` into the temp file. A `ZERO` extends the file and punches the range (§4.7) instead.
4. One `fsync` at commit, not per packet.

The file is the reassembly buffer. The receiver does not queue out-of-order payloads in a second byte buffer.

### 7.3 Where this runs

The fast path is Linux io_uring on the helper. That backend is not in this repo: nothing here pretends to submit `READ_FIXED` or `SEND_ZC`. macOS and the portable build use `pread` / `pwrite` and `sendmsg` / `recvmsg` with the same frames. Tests for loss, reorder, and AEAD run without a NIC, in process, on either OS. Path open on Linux is `openat2` as in §3.4. The Darwin build walks each component with `O_NOFOLLOW`. That walk is not `openat2` and must not be described as if it were.

`O_DIRECT`, `sendfile`, and `splice` are not in v1. They skip the place the cipher has to run, or they fight the page cache for small datagrams.

### 7.4 Socket buffers, batching, and agent install notes

A paced sender still bursts: a late wake-up sends up to 1 ms of data at once (§6), and a receiver that stops reading for a moment (a page fault, a `fsync`, the 1 MiB hash step of §4.7) has only its socket buffer between the burst and a drop. The OS defaults are small: 208 KiB on most Linux kernels, 768 KiB of UDP receive space on Darwin.

Both peers ask for 8 MiB of `SO_RCVBUF` and `SO_SNDBUF` when the socket opens. A refused size (Darwin returns `ENOBUFS` above `kern.ipc.maxsockbuf`) is halved and retried, down to 64 KiB, then the default stays. The granted size is read back with `getsockopt` and reported as `getsockopt` gives it: Linux reports twice what it allows for data, because it doubles the request for its own bookkeeping, and caps the request at `net.core.rmem_max` and `net.core.wmem_max` without an error. An unprivileged process cannot raise those caps, and the helper runs as the dropped identity user, so it does not try (`SO_RCVBUFFORCE` needs `CAP_NET_ADMIN`), and sahxfer never writes a sysctl.

Reported: `recv`'s `ready` event carries `rcvbuf`, the granted receive buffer in bytes (PROTOCOL.md §1.1). With `--diag`, `put`, `get`, and `recv` write `diag rcvbuf=<n> sndbuf=<n>` on stderr when the socket opens. The data receiver then checks once a second: when its usable receive buffer (the granted size, half of it on Linux) is below `rate * max(RTprop, 5 ms)`, with `rate` its measured arrival rate in wire bytes and `RTprop` its least RTT sample, it writes one `diag warn rcvbuf=<n> usable=<n> need=<n> rate=<B/s> rtt=<d>` line with `--diag` and no more for that run. Without `--diag` stderr keeps its contract (a code on failure, nothing else). `max(RTprop, 5 ms)` is the round length of §6: the cap lets about one round of data be in flight, and a receiver that stalls for one round needs that much buffer to lose nothing.

Reading when there is work. When the engine has work due now, the runner's read must not block, but it must still read. It used to set a read deadline of now; Go returns a timeout for a deadline already passed without calling `recvfrom`, so a peer with continuous work read nothing until it went idle. A sender sealing six 1 MiB `ZERO`s back to back (about 7 ms each under CPU load) left the receiver's `PING` unread for 40 ms, the receiver's only RTT sample became 51 ms, its `FEEDBACK` interval `srtt / 4` became 12.7 ms, longer than the `2 * 5 ms` the cap needs to grow past `10 * MSS`, and the controller stayed at 1 MB/s for the whole grant. A zero wait is now one non-blocking receive (`MSG_DONTWAIT` through `syscall.RawConn`, deadline cleared). Linux loopback in the golang:1.27 container is bimodal and this fix does not settle it: 30 MB of random data takes either 0.8 to 1.3 s or 20 to 25 s, with and without it, and `TestLoopbackThroughput30MB` fails there most runs at the previous commit and now. In a slow run the sender's cap stays near `2 * bw * 5 ms` (about 20 KB) with in-flight bytes below it and the estimate near 2 MB/s, which is the `10 * MSS` per `FEEDBACK` interval arithmetic of §6: a `FEEDBACK` interval longer than 5 ms makes `bw = cap / interval` a fixed point. Open; it needs its own change to §6. With twelve busy processes on the build host, a 300 MB file that is 52% zero went from not finishing in 120 s to 30 to 43 s (the old build, all `DATA`: 41 to 62 s). The engine also lets datagrams it has already sealed in a `Pump` (a `PONG`, a `FIN`) leave before it starts the hashing a `ZERO` costs.

Batching, Linux only (build tag `linux`). The receive loop takes up to 32 datagrams per `recvmmsg` and pumps the engine once per batch; the send path hands every datagram one `Pump` produced to `sendmmsg`, retrying the remainder of a partial send. Both use `golang.org/x/sys/unix` syscall numbers with `Msghdr` and `Iovec`; they wait through the Go netpoller (`syscall.RawConn`), so read deadlines and cancellation behave as before. Measured with `strace -c` on 10 MB in the container: the receiver's socket calls fell from 11,242 (`recvfrom` and `sendto`) to 7,817 (`recvmmsg` and `sendmmsg`, about 1.8 datagrams per `recvmmsg`); the sender's stayed near 16,900, because one `Pump` produces about one datagram and the zero-wait read polls. Socket calls are 2 to 4% of syscall time on either side; Go's `futex` and `nanosleep` are about 90%. A listener's source address comes from each message's `msg_name` and is pinned exactly as before; a datagram from another source in the same batch is dropped. Darwin and the portable build keep one `recvfrom` and one `sendto` per datagram.

Agent install notes. On a Linux host that runs the helper, set, as root, in `/etc/sysctl.d/90-sahxfer.conf`:

```
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
```

then `sysctl --system`. 16 MiB leaves the 8 MiB request whole after Linux doubles it. At 1 Gbit/s and a 50 ms RTT the formula above asks for about 6 MB; at the 5 ms floor, 0.6 MB. On the Darwin build host (`kern.ipc.maxsockbuf` 8 MiB) the 8 MiB request is granted whole for both buffers. The values are a recommendation for the host install, not something the helper or the agent sets.

## 8. Relay

Default placement. The relay is a process with the grant table of `transfer_id → route_token, two pinned 4-tuples, expiry`. It is not the SystemAPI request worker. A bulk flow must not share a thread pool with ticket issuance. The grant's `peer.udp` is the relay address.

On a packet:

1. Magic and version match, and the datagram is at least 80 bytes. Otherwise drop.
2. Look up `transfer_id`. Unknown id: drop.
3. Compare `route_token` by hashing both sides with SHA-256 and then a constant-time compare. Mismatch: count it, drop. At 32 mismatches, forget the grant and tell SystemAPI `auth`.
4. If this direction has no pinned 4-tuple, pin the source address. If it has one and the source differs, drop. A third peer cannot join.
5. Forward the datagram unchanged to the other pinned peer. If the other peer is not pinned yet, hold at most one datagram per direction for `1 s`, then drop.

The relay does not log the route token. It does not rewrite seq or offset. It does not fragment. It applies two per-grant budgets, then forgets the grant and reports `byte_cap`. `DATA` payload, retransmissions included, is charged against `byte_cap`. Every other datagram is charged its whole length against `byte_cap + 256 MiB`. Without the second budget a key holder could push unbounded 88-byte `ZERO`s, or any control frame, through the relay. The allowance covers an honest grant: `FEEDBACK` at its 5 ms floor for the 3600 s maximum is 92 MB, and `ZERO`s cost at most 88 bytes per `MSS` of the file, under 8% of `size`, which `byte_cap` already covers.

The agent reaches the relay by sending the first packet itself (outbound), the same way it phones home. The client's first packet pins the other side. Order does not matter.

## 9. QUIC

ALPN is `sahxfer/1`. TLS 1.3 only. The certificate chains to the system pool and the name matches the grant. If the grant also carries an SPKI pin, the pin must match too. No skipped verification. No 0-RTT. A 0-RTT write can be replayed, and v1 does not need the handshake savings.

QUIC is a pipe for the same grant. It is not a second authorization path.

### 9.1 Bridge (`quic-bridge`)

The client opens one QUIC connection to the bridge for one grant. Each QUIC DATAGRAM is one sealed sahxfer frame, header through tag, exactly as it would appear in a UDP payload. The bridge runs the relay rules in §8, with the QUIC connection identity in place of the client's UDP 4-tuple, and forwards to the agent's UDP 4-tuple.

The bridge does not have `key`. It cannot open a frame.

Backpressure: if the UDP-bound queue for the grant exceeds 4 MiB, the bridge stops reading QUIC datagrams. It does not grow the queue. The two controllers stay unstacked because sahxfer pacing is off and QUIC paces the client-to-bridge hop. The bridge-to-agent UDP hop is paced by the agent's own receive window only in the sense that the bridge's 4 MiB cap is the buffer. That cap is the specification. Do not raise it to "be safe".

One connection, one grant. A second grant is a second connection.

### 9.2 QUIC to QUIC, datagram mode (experimental)

Both peers speak QUIC. DATAGRAMs carry sealed sahxfer frames. Reliability is still NACK, because QUIC datagrams are not reliable. Congestion control is QUIC's alone. Inner pacing is off. This is the mode to measure when a network already carries QUIC well and raw UDP poorly.

A relay in this mode forwards DATAGRAMs without the key, same rules as §8, and is still experimental.

### 9.3 QUIC to QUIC, stream mode (experimental)

One unidirectional stream carries the raw file, exactly `size` bytes, then a stream FIN. There is no 64-byte header and no NACK. QUIC provides reliability and congestion control. The receiver hashes while it reads. A short stream or a stream longer than `size` is `protocol` and deletes the temp file.

The receiver opens its own unidirectional stream and writes the 32-byte SHA-256, then FINs. The sender checks it against the grant.

This mode is endpoint to endpoint. A bridge would terminate QUIC and see plaintext, which v1 does not allow. Stream mode pays head-of-line on loss. It exists so a peer with a stock QUIC stack and no sahxfer pacer can still move a file under the same grant and the same path rules. It is not the fast path.

## 10. State machine

Sender (the peer with the file):

| State | Enter | Leave |
| --- | --- | --- |
| `PINGING` | Grant accepted locally. | First `PONG`, or abort. |
| `SENDING` | First `PONG`. New bytes remain. | Every byte transmitted once (`FLUSHING`), or abort. |
| `FLUSHING` | `FIN` started. | `DONE` accepted (`DONE`), or abort. |
| `DONE` | `DONE` checked out: hash matches, size matches. `CLOSE_ACK` set on further `FIN`. | Grant discarded after the result is reported. |
| `ABORT` | Local or peer abort. | Terminal. |

Receiver:

| State | Enter | Leave |
| --- | --- | --- |
| `RECEIVING` | First authentic packet. | Hole map empty and `FIN` seen (`VERIFYING`), or abort. |
| `VERIFYING` | Hash folded over `[0, size)`, fsync, rename. | `DONE` sent. |
| `DONE` | Result reported. | Terminal. |
| `ABORT` | Local or peer abort. Temp file deleted. | Terminal. |

A `DATA` that arrives in `VERIFYING` for an already-filled range is ignored. A `DATA` that fills a hole the receiver had missed re-enters `RECEIVING`. The receiver does not rename until it is back in `VERIFYING` with an empty hole map.

## 11. Limits

| Setting | Default |
| --- | --- |
| Time to first packet | 60 s |
| Idle | 30 s |
| Hard max | 3600 s |
| File cap | tenant policy, recommended 256 GiB |
| Live grants per actor | 2 |
| Auth failures per grant | 32 |
| NACK holes per packet | 32 |
| `ZERO` length | 1 MiB |
| Relay hold when the peer is unknown | 1 datagram, 1 s |
| Bridge queue | 4 MiB |

A limit breach aborts. It does not truncate and commit.

## 12. What v1 does not do

- Directory trees, delete, or an rsync delta. That stays `sahsync`.
- More than one file per grant.
- Resume. A failed grant deletes the temp file. A new grant starts at offset 0. Resume needs a prefix hash and a new grant that names a kept temp file. That is a later spec, and it is not implied by this one.
- NAT hole punching, `crypto=off`, 0-RTT, a decrypting bridge, `O_DIRECT`, `mmap` send.
- Sharing the SystemAPI WebSocket as a fallback byte path. If UDP and QUIC are both blocked, the transfer fails. The operator uses `sahsync`.

## 13. Build order

Each phase is shippable on its own. None of them edit SystemAPI until phase 3.

1. In-process frames. Seal, open, hole map, NACK maturity, `FIN`/`DONE`, negative tests for tag, wrap, replay, reorder, and hash mismatch. No sockets.
2. UDP between two local processes. Paced BBRv3 driven by `FEEDBACK`. Linux io_uring behind the same buffer interface as `pread`/`pwrite`. Loss injected on a test socket.
3. Grant API on SystemAPI and the agent push, as a change to that repo and to `sah-suite.md` together. Path rules and the helper land here. sahxfer's client starts calling it.
4. Relay, with the 4-tuple pin and the auth-failure budget.
5. `quic-bridge`.
6. Experimental `quic-datagram`, then experimental `quic-stream`.

Phase 1 does not add a Go module until the frame tests have a directory to live in. When it does, the module path is `github.com/afterdarksys/sahxfer`.

## 14. Tests that must fail closed

- Tampered tag, truncated datagram, bad magic, version 2, unknown type, unknown flag, non-zero unused flag on `DATA`: no byte is written.
- `offset + length` wraps, or runs past `size`: abort, temp file gone.
- Replayed `DATA`: `delivered_bytes` does not increase, file size does not change.
- Reorder of the last packet before the first: the file hashes correctly, and no NACK fires before the hole is mature.
- Dropped NACK: a later NACK still causes the missing range to arrive.
- Dropped `FIN`: the sender's RTT timer sends another, and the receiver still commits.
- `DONE` hash differs from the grant: sender aborts, does not report `ok`.
- `xfer:get` grant rejected by the helper if a put lease is all it has.
- Ticket or grant for host A presented to host B: drop.
- Root `/srv/a` does not open `/srv/b`. `../`, absolute `path`, and a symlink component: refused before any `DATA`.
- `overwrite:false` and an existing target: `exists`, target bytes unchanged.
- Second source 4-tuple for a pinned transfer: relay drops it.
- Wrong route token: relay drops it and does not pin.
- The 32nd AEAD failure, or the 32nd route-token mismatch: grant dead, temp file gone. A mismatch is counted once. The packet is not also opened.
- `quic-datagram` with inner pacing enabled: the test fails. The controller must be off.
- Logs from a transfer fixture do not contain the bearer, the key, or the route token.
- `ZERO` past `size`, wrapping, of length 0 or above 1 MiB, with a payload other than 8 bytes, or sent to a receiver that did not set `ZERO_OK`: abort with `protocol`, temp file gone. A receiver without `ZERO_OK` receives only `DATA` and the file is identical. A `ZERO` over bytes that are not zero in the grant's file: `hash_mismatch`, target untouched.

## 15. Decisions recorded with this spec

- SAH authorizes. It does not carry the file.
- Repair is NACK. Close is `FIN` plus `DONE`, because a NACK-only sender cannot know the receiver finished.
- Congestion is pace-bbr on `FEEDBACK`, and it is off when QUIC is already pacing.
- The temp file is the reassembly buffer. First write at an offset wins.
- Cipher is ChaCha20-Poly1305 with a direction-and-seq nonce. The route token is 128 bits even though the other fields are 64-bit, because a 64-bit admission secret can be guessed.
- The relay and the QUIC bridge forward sealed frames and never receive the key.
- `put` ships before `get`. The frame format is the same.
- Zero runs travel as `ZERO` (§4.7), negotiated by a probe-id bit, not a version. General compression waits for a v2 that moves bytes off file offsets.
