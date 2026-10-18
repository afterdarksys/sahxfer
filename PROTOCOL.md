# sahxfer protocol

Version 1. One grant moves one regular file in one direction. SAH authorizes the grant. The file bytes travel in sealed datagrams, not on the agent WebSocket.

`docs/design.md` is the working spec. This file is the wire protocol a peer implements. Congestion in this repository is pace-bbr, a tested subset of the BBRv3 shape, not a byte-identical BBRv3. The portable I/O path is `pread` / `pwrite`. The CLI speaks UDP. `internal/quic` implements the QUIC pipe. The CLI does not call it, and a QUIC grant still returns `agent_unsupported`.

## 1. Grant

The client sends one credential in a header. `Authorization: Bearer` carries the sahconnect device-login token, and only when that token is bound to the request origin. `X-API-Key` is the other credential. The two are not sent together. Credentials never appear in a query string or in a UDP field.

```
GET /api/v1/hosts/resolve?name=<host>
POST /api/v1/xfer/grant
```

The grant request names `host_id`, `purpose` (`xfer:put`, `xfer:get`, or `xfer:root`), `dir` (`put` or `get`), absolute `root`, relative `path`, `size`, `sha256`, `overwrite`, and a requested `transport`. `size` is a byte count from 0 through `2^63-1`. A larger value is `too_large`. Size 0 is an empty file.

The response carries `grant_id`, `transfer_id` (64-bit demux id, not a secret), `expires_at` (the first-packet deadline, issue plus `expires_in`), idle, max (the hard stop is issue plus `max_seconds`, at most 3600 s), `byte_cap`, the path and hash the client asked for, `profile` (`internet` or `dc`), the chosen `transport`, `peer.udp` and `peer.quic`, `aead` (`ChaCha20-Poly1305`), a 32-byte `key`, and a 16-byte `route_token`. Both secrets come from the OS CSPRNG. The client checks host, purpose, root, path, size, and hash before it sends a packet.

`profile` and `transport` are server choices. The client cannot select `dc` or turn the cipher off. An unknown transport is `mismatch` in this repository's client.

The same key, route token, transfer id, path, size, and hash are delivered to the host agent on its existing channel, under a `systemapi-lease-v1` lease the agent verifies. The lease payload is 18 lines (`docs/design.md` §3.4): grant id, deadline, `start` or `renew`, `put` or `get`, root, path, size, sha256, overwrite, transfer id, first-packet deadline, idle, max, byte cap, profile, transport, peer mode, and the hex of `sha256("sahxfer-material-v1\n" || key || route_token)`. `docs/golden-xfer-lease-v2.txt` is the shared vector. The peer mode is `listen` (the host binds and `peer.udp` is the address it reported) or `dial:<host:port>` (the host dials a relay, which is `peer.udp`). `peer.udp` is always where the client sends. A listening host pins the first source whose datagram opens, never an unauthenticated one. The server that issues the grant is not in this repository. `sahxfer grant` can write a mode-0600 bootstrap file so two local processes can run the data plane. A grant that arrived over HTTPS stays in memory.

The receiver reports the result to the server: the agent for `put`. The client does not report a put. `xfer:put` is client to host. `xfer:get` swaps the peers: the agent sends, the client receives. One grant is one file. A failed transfer deletes the temp and a new grant starts at offset 0.

### 1.1 Host helper (`recv` agent mode)

The agent verifies the lease, then spawns `sahxfer recv --ctl-fd 3 --event-fd 4` as the identity user with only fds 0 to 4 open. The key travels only on fd 3. Never argv, never env, never disk.

Fd 3, agent to recv, one JSON object per line. The first line is the grant: `v` (1), `grant_id`, `transfer_id`, `purpose`, `dir`, `root`, `path`, `size`, `sha256`, `overwrite`, `profile`, `transport`, `aead`, `key`, `route_token`, `expires_unix` (first-packet deadline), `deadline_unix` (lease deadline), `idle_s`, `max_s`, `byte_cap`, `peer` (`listen:<ip:port>` to bind, port 0 for ephemeral, or `dial:<host:port>`). Unknown fields are refused; the line is capped at 64 KiB and then checked like any grant. The hard stop is the earlier of `deadline_unix - 60 + max_s` and now plus `max_s`. Later lines carry exactly the keys of their op: `{"op":"renew","deadline_unix":<n>}` and `{"op":"cancel","reason":"<code>"}` (`reason` optional). A deadline only moves forward; a renew that does not is refused with `{"ev":"refused","op":"renew","reason":"deadline_not_forward"}` on fd 4 and the old deadline stays. EOF is cancel with reason `stopped`. Any other line, or an extra key, stops the run with reason `protocol`. Fds 3 and 4 must be a pipe or a socket. recv waits at most 10 s for the grant line; a signal ends the wait at once.

Fd 4, recv to agent: `{"ev":"ready","udp":"<bound addr>","rcvbuf":<n>}` (`udp` only when listening; `rcvbuf` is the granted `SO_RCVBUF` as `getsockopt` reports it, which on Linux is twice the usable size, `docs/design.md` §7.4), `{"ev":"active","bytes":<n>}` on the first authentic packet and then at most once a second, and last `{"ev":"result","grant_id","transfer_id","status","reason","bytes","sha256","committed"}`. `status` is `ok`, `hash_mismatch`, `aborted`, `expired`, or `io_error`. `reason` is an ABORT name (§4.4), `stopped`, or, for a refusal before `ready`, the local code (`exists`, `symlink_refused`, `not_a_file`, `bad_path`, `no_space`). `sha256` is present only when `committed` is true. A commit is `ok` even if `CLOSE_ACK` never came. A grant line that does not arrive or does not decode produces one `{"ev":"result","status":"aborted","reason":"<code>","committed":false}`, without `grant_id` or `transfer_id`, and the code on stderr (`bad_grant` for a line that never came, `cancelled` for a signal).

A cancel, EOF, or lapsed lease sends one `ABORT cancelled` to the peer, deletes the temp, and reports the reason (`expired` for a lapsed lease). After the commit it sends nothing: the target is final, and the result is `ok`. Stdout and stderr are unchanged: three lines on success, one code on failure.

`recv --sweep --ctl-fd 3` reads one line `{"root","path","grant_id"}` and removes only `.sahxfer-<grant_id>.part` in the parent of `path`.

## 2. Datagram

One UDP datagram is one frame. There is no segmentation under the datagram. A frame that does not fit is not sent.

The first four bytes are `53 41 48 58` (`SAHX`). Every later integer is little-endian. Version, type, and flags sit in the first eight bytes. The other integers are 64-bit.

```
offset  size  field
0       4     magic SAHX
4       1     version = 1
5       1     type
6       2     flags
8       8     transfer_id
16      8     seq
24      8     offset
32      8     payload_len
40      8     send_time_ns
48      16    route_token
64      N     ciphertext
64+N    16    Poly1305 tag
```

The header is 64 bytes. The tag is 16 bytes. Overhead is 80. The datagram length must equal `80 + payload_len`. Any other length is dropped.

`seq` starts at 1 in each direction. Sequence 0 and `2^64-1` are rejected. A peer never reuses a sequence under the same key and direction. A wrap aborts the grant.

`send_time_ns` is the sender's duration since the shared epoch. A UDP runner uses one epoch for the life of the process. A zero epoch means Unix time in nanoseconds on both processes.

A version other than 1 is dropped before AEAD. The grant is not aborted, and no byte is written.

Plaintext caps:

| Profile | Datagram | Plaintext |
| --- | --- | --- |
| `internet` | 1232 | 1152 |
| `dc` | 8192 | 8112 |

v1 does not probe the path MTU. The cap stays at the profile the grant issued. `dc` is a plaintext cap. It does not turn pacing off.

## 3. AEAD

ChaCha20-Poly1305 (RFC 8439). The 64-byte header is associated data. The plaintext is the payload. The tag is the last 16 bytes. There is no cipher negotiation and no `crypto=off`.

The 12-byte nonce is little-endian:

```
byte 0      direction   0 = client, 1 = agent
bytes 1..3  0
bytes 4..11 seq
```

Each direction has its own sequence space. The same sequence from the client and the agent does not share a nonce.

The route token is compared by SHA-256 of both sides, then a constant-time compare. A mismatch is not opened. A failed tag check drops the packet. It is not NACKed and it is not answered. The 32nd route-token mismatch, or the 32nd failed open, aborts the grant with `auth` and wipes the key. The two counters are separate. A mismatch is counted once. A listening peer counts only after it has pinned a source: before the first authentic datagram, failures from any source are dropped uncounted, so a stranger who can reach the listen port cannot spend the budget and kill the grant before the real peer arrives.

## 4. Types

| Type | Code | Payload |
| --- | --- | --- |
| `DATA` | 1 | File bytes. `offset` is the file position. |
| `NACK` | 2 | Hole list. `offset` is the highest contiguous byte. The receiver holds `[0, offset)`. |
| `FEEDBACK` | 3 | 48-byte congestion sample. Not a repair request. |
| `FIN` | 4 | Empty. `offset` is the file size. The sender has put every byte on the wire at least once. |
| `DONE` | 5 | 32-byte SHA-256. `offset` is the file size. Sent only after fsync and rename. |
| `ABORT` | 6 | One `u64` reason. |
| `PING` | 7 | Empty. `offset` is the probe id. Bit 62 of a receiver's probe id is `ZERO_OK` (§4.5). |
| `PONG` | 8 | `u64 echo_send_time_ns`, `u64 receiver_delay_ns`. `offset` echoes the probe id. |
| `ZERO` | 9 | One `u64 length`. `offset` is the file position. `[offset, offset+length)` is all zero bytes. Sent only to a receiver that set `ZERO_OK` (§4.5). |

An unknown type on an authentic packet aborts with `protocol`. A receiver that did not set `ZERO_OK` treats `ZERO` as unknown.

Flags:

| Bit | Value | Name | Legal on |
| --- | --- | --- | --- |
| 0 | 1 | `RETX` | `DATA` and `ZERO`. This range is a retransmission. |
| 1 | 2 | `CLOSE_ACK` | `FIN` only, and only after the sender has accepted a valid `DONE`. |

Any other bit, or a legal bit on the wrong type, aborts with `protocol` after the packet opens.

`offset + payload_len` uses a checked add. Wrap, or a span past `size`, aborts with `protocol` when the packet is authentic. `DATA` with length 0 aborts with `protocol` when `size` is greater than 0. An empty file has no `DATA` and no `ZERO`. For `ZERO` the span is `offset + length`, under the same checks.

### 4.1 NACK

```
u64 hole_count          // 0..32
hole_count times:
    u64 start           // inclusive
    u64 end             // exclusive
```

Holes are ordered, non-overlapping, and each `start < end <= size`. A hole is mature when a byte past its end has been accepted, or when it is older than `max(3 * srtt, 1 ms)` and any later sequence has been accepted. The trailing edge is not a hole. A NACK whose `offset` is above the bytes the sender has sent once aborts with `protocol`: the receiver cannot hold a contiguous byte that never left. The receiver sends a NACK at least once per smoothed RTT while a mature hole exists, and again as soon as a hole becomes mature.

### 4.2 FEEDBACK

Fixed 48 bytes:

```
u64 echo_send_time_ns
u64 delivered_bytes
u64 newly_lost_bytes
u64 highest_seq_received
u64 ecn_ce_count
u64 recv_rate_bps
```

`offset` is the highest contiguous file byte, the same value as on a NACK, and above the bytes the sender has sent once it aborts with `protocol`. `highest_seq_received` is the highest `seq` of a `DATA` that added bytes the receiver did not hold; a duplicate does not raise it, and it never decreases. The sender's stall-probe undo depends on this. Cadence is `max(5 ms, srtt / 4)`, and at least every 64 accepted `DATA` packets. The sender retransmits on NACK, plus a stall probe. FEEDBACK does not request a retransmission.

pace-bbr uses this sample. It runs on UDP. `quic-datagram` and `quic-bridge` turn inner pacing off, because QUIC already paces that hop.

### 4.3 Close

`FIN` and `DONE` are the close signals. They are not per-packet acknowledgements.

- The sender, after every byte has been transmitted once, enters `FLUSHING` and sends `FIN` every RTT.
- The receiver commits, then sends `DONE` every RTT until a `FIN` with `CLOSE_ACK` arrives, or until idle.
- The sender accepts `DONE` only when the hash and the size match the grant, then sets `CLOSE_ACK` on later `FIN`.
- In `SENDING` or `FLUSHING`, if bytes above the contiguous offset are in flight and neither that offset nor `delivered_bytes` has advanced for `W = 2 * max(srtt + 4 * rttvar, 5 ms)` (1 s before the first RTT sample), the sender retransmits its highest in-flight segment with `RETX`. If that is followed by no progress for `max(2 * W, 1 s)`, it retransmits every in-flight range older than the repair timeout (`2 * srtt`) with `RETX`, doubling that wait per repeat up to 8 s. In `FLUSHING` the sender keeps sending `FIN`.

Give-up is `max_seconds` or `idle_seconds`, then `ABORT` with `expired` or `idle`.

Empty file: `PING`, one `PONG`, `FIN` with `offset` 0. The receiver commits a 0-byte file and sends `DONE` with SHA-256 of the empty input:

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### 4.4 ABORT

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

`ABORT` is best-effort. The grant is then dead. The receiver deletes the temp file. A later `DATA` for a dead grant is dropped.

### 4.5 ZERO

A run of zero bytes in the file travels as one `ZERO` frame instead of `DATA`. Offsets stay file offsets, the hole map and NACK are unchanged, and the hash is still SHA-256 of the whole file.

Negotiation. The receiver sets bit 62 (`0x4000000000000000`, `ZERO_OK`) in the `offset` of every `PING` it sends. Probe ids are counters and never set bits 62 or 63 otherwise. A sender sends `ZERO` only after an authentic `PING` with `ZERO_OK`; until then, and always for a receiver that never sets it, zero bytes go as `DATA`. A sender ignores the bit on `PONG`. A v1 sender echoes the probe id in its `PONG` and does not read it, and a v1 receiver never sets it, so neither old peer sees a change. The datagram version stays 1.

Payload, exactly 8 bytes:

```
u64 length      // 1 .. 1048576, and offset + length <= size
```

Receiver, after the packet opens: a payload other than 8 bytes, `length` 0, `length` above 1 MiB, a wrap, a span past `size`, `size` 0, or a receiver that did not set `ZERO_OK`: abort with `protocol`. Otherwise every byte of the span the hole map still lacks is made to read as zero (the temp file is extended to cover it, and the range may be deallocated, §5), the span is accepted into the hole map as `DATA` would be, and the streaming SHA-256 folds those zero bytes in order. `delivered_bytes`, `highest_seq_received`, the idle timer, `byte_cap`, and the `active` and `result` byte counts treat a `ZERO` exactly as `DATA` of `length` bytes. First write wins as for `DATA`.

Sender. With `ZERO_OK`, each new block of `MSS` bytes at a multiple of `MSS` (the last block of the file may be shorter) is compared with zero before it is sealed. A zero block starts a run; following zero blocks extend it, up to `floor(1 MiB / MSS) * MSS` bytes or the end of the file. A run of at least `MSS` bytes is one `ZERO`. A run that is only a short final block is `DATA`. A repair reads its range again and uses `ZERO` for a zero prefix of at least `MSS` bytes or for the whole remaining range, otherwise `DATA`. A hole inside a zero run is repaired with `ZERO`. Either frame carries the same bytes at the same offset, so the one-plaintext rule (§5) holds.

Charge. A `ZERO` costs the sender 88 bytes, its datagram, in the pacer and the in-flight cap, and a lost `ZERO` counts 88 bytes of loss. The pacer's delivery count, with `d = min(delivered_bytes, bytes sent once)` and `contig` the highest contiguous offset, is `(contig - Zb) + max(0, d - contig - Za)`: `Zb` is `length - 88` summed over the `ZERO`s sealed for the first time that lie wholly below `contig`, `Za` the same over the others. It is exact below `contig` and can only fall short above it, never exceed the wire bytes delivered, so neither a zero run nor a peer that reports more than the file can raise the bandwidth estimate.

## 5. Reliability

The sender keeps the file. A retransmission reads the range again, seals it under a new sequence, and sets `RETX`. The plaintext at an offset is fixed for the life of the grant.

The receiver writes the temp file with `pwrite`. A `ZERO` span is written as a hole: the temp file is extended with `ftruncate` when it is shorter than the span's end (never shrunk), then the block-aligned inside of the span is deallocated with `fallocate(PUNCH_HOLE|KEEP_SIZE)` on Linux or `F_PUNCHHOLE` on Darwin where the filesystem supports it, and nothing more elsewhere. The temp was created empty and a range the hole map lacks was never written, so it reads as zero once the file covers it. The first write at an offset wins. A replay of the same bytes is a no-op. The streaming SHA-256 folds only the contiguous prefix. Out-of-order ranges sit in the file until the gap in front of them closes.

The hole map starts as `[0, size)`. It holds missing ranges, not file bytes.

`byte_cap` counts unique file bytes sealed for the first time and unique bytes accepted, a `ZERO` by its `length`. A retransmission does not add to the cap. Exceeding the cap aborts with `byte_cap`. The relay charges a `ZERO` its 88 bytes against its control budget (§6).

Commit order on the receiver: hole map empty, streamed SHA-256 equals the grant, `fsync` the temp file, `fsync` the parent directory, then rename. `DONE` is sent after that. A hash mismatch deletes the temp and does not rename. `overwrite` false uses `renameat2(RENAME_NOREPLACE)`. The temp name is `.sahxfer-<grant_id>.part`, created `O_CREAT|O_EXCL|O_NOFOLLOW|O_RDWR`, mode 0600.

Linux opens the root and the path with `openat2` (`RESOLVE_BENEATH`, no symlinks, no magic links). A kernel without `openat2` is `agent_unsupported`. Darwin walks each component with `O_NOFOLLOW`. That walk is not `openat2`.

## 6. Relay

The default path is a relay that does not have the key. Both peers send UDP to it. Direct UDP is used only when policy says the host published a reachable address. NAT hole punching is out of v1.

On a packet the relay checks magic and version, requires at least 80 bytes, looks up `transfer_id`, and compares the route token as in section 3. The first source 4-tuple in each direction is pinned. A different source is dropped. A third peer cannot join. The datagram is forwarded unchanged. When the other peer is not pinned yet, the relay holds one datagram for 1 second.

The 32nd token mismatch forgets the grant and reports `auth`. The forwarding cap is the grant's byte cap, charged with `DATA` payload. Every other datagram, `ZERO` included, is charged its whole length against a second budget of `byte_cap + 256 MiB`; past either, the relay forgets the grant and reports `byte_cap`. The relay does not log the route token, rewrite sequence or offset, or fragment.

## 7. QUIC

QUIC is a pipe for the same grant. It is not a second authorization path. ALPN is `sahxfer/1`. TLS 1.3 only. The certificate chains to the system pool and the name matches the grant. A 32-byte SPKI pin, when the dialer is given one, is SHA-256 of the leaf `RawSubjectPublicKeyInfo` and is checked after the chain and the name. Any other pin length fails closed as `auth` before the dial. Verification is not skipped. 0-RTT is not used.

| Transport | What moves |
| --- | --- |
| `udp` | Sealed frames on UDP. pace-bbr on. This is what the CLI runs. |
| `quic-bridge` | One QUIC connection per grant. Each DATAGRAM is one sealed frame. The bridge applies the relay rules and does not have the key. The UDP-bound queue stops at 4 MiB. Inner pacing is off. |
| `quic-datagram` | Both peers on QUIC. DATAGRAMs carry sealed frames. Reliability is still NACK. Congestion is QUIC's. Inner pacing is off. |
| `quic-stream` | One unidirectional stream of exactly `size` raw bytes, then stream FIN. No 64-byte header and no NACK. The receiver hashes while reading. A short stream or a stream longer than `size` is `protocol` and deletes the temp. The receiver writes the 32-byte SHA-256 on its own unidirectional stream. Endpoint to endpoint. The bytes are inside QUIC TLS and are not sealed again. |

A sealed internet frame is 1232 bytes. `quic-datagram` on the `dc` cap (8192) does not fit the default QUIC datagram bound and fails closed as `protocol`.

## 8. Limits

| Setting | Value |
| --- | --- |
| Time to first packet | 60 s |
| Idle | 30 s, at most 3600 s |
| Hard max | 3600 s |
| Auth failures | 32 per counter |
| NACK holes | 32 |
| `ZERO` length | 1 MiB |
| Relay hold | 1 datagram, 1 s |
| Bridge queue | 4 MiB, UDP-bound bytes for that grant |

A limit breach aborts. It does not truncate and commit.

## 9. Out of v1

Directories, delete, rsync deltas, more than one file per grant, resume, NAT hole punching, `crypto=off`, 0-RTT, a decrypting bridge, `O_DIRECT`, `sendfile`, `splice`, and `mmap` of the fast path. If UDP and QUIC are both blocked, the transfer fails. The operator uses `sahsync`.
