# sahxfer get direction plan

Status: plan, 2026-10-18. Nothing here is implemented. It follows `docs/plans/2026-10-18-end-to-end-wiring.md` (put, shipped in sahxfer 90535f8 and systemapi fd41171) and replaces that plan's phase-2 get paragraph. It covers sahxfer, the systemapi server (`/Users/ryan/development/systemapi.io-xfer`), and `systemapi-agent/` there. It does not depend on the internals of `internal/engine`, `internal/frame`, or `internal/safeio`, which are being changed for zero-run skipping; it uses only their exported calls that exist today (`engine.New`, `Peer.Committed`, `Peer.Delivered`, `safeio.OpenRoot`, `Root.OpenRegular`, `Root.RemoveTemp`, `safeio.CreateNew`).

## What exists today that get builds on

- `sahxfer get --url` exists (`internal/cli/xfer.go` urlGet): it asks for a grant with `AdoptMeta`, checks it, picks the local destination (`destFile`), creates `.sahxfer-<grant_id>.part` (`newLocal`), dials `peer.udp`, and runs the receiver, which verifies the streamed SHA-256 against the grant before it commits and sends `DONE`.
- `decodeGrant` with `AdoptMeta` takes size and hash from the response and still checks host, purpose, root, path, overwrite, and every bound (`internal/control/client.go`, the AdoptMeta branch). `changed` and `not_a_file` are already in `allowErr`.
- The recv agent mode already runs as a sender when the grant line says `dir:"get"` (`internal/cli/agent.go` recvAgentRun: `OpenRegular`, size check, full re-hash, `changed`). Two defects there: a size change returns `mismatch` instead of `changed`, and `outcome` maps a sender that finished cleanly (err nil, committed false) to `aborted protocol`.
- The data plane is role-agnostic about who listens. `internal/udp/udp.go` queues a listener's output until a datagram opens under AEAD, then pins and flushes; the receiver sends a PING first (`engine.go` Pump), the sender pings too, and `maybeRePing` sends one more PING after the first authentic packet if all earlier ones predate it. So a dialing receiver and a listening sender work with no engine change.
- The server refuses get (`playground/xfer.js` grant: `request.dir !== 'put'` is `agent_unsupported`), and so does the agent (`systemapi-agent/xfer.go` grant: "get is phase 2"). `end()` deletes the grant from the map on the first result, so a second result has nowhere to land. The agent's state record (`xfer_state.go` xferRecord) has no `dir`.

## Decisions

1. Prepare is its own step with its own lease and its own short-lived helper. The server cannot sign the 18-line start lease without size and hash, and only the identity user may open the file. The server sends `xfer_prepare`; the agent verifies a 7-line prepare lease, spawns `sahxfer recv --prepare --ctl-fd 3 --event-fd 4` as the identity, and forwards two events: `stat` (size, as soon as `fstat` returns) and `prepared` (size and sha256). Splitting stat from hash lets the server size its timeout from the real file and refuse an oversize file before a byte is hashed. Rationale for a separate helper rather than reusing the sending process: the start lease does not exist yet when hashing happens, and a process that holds no key cannot leak one.

2. Held HTTP request in v1, not 202 and poll. The client already blocks on the grant call for put, and the server already holds the request until `ready`. Timeout rule, all server side: 10 s from `xfer_prepare` to the `stat` event (the existing ready timeout), then `min(10 + ceil(size / 100 MiB), SYSTEMAPI_XFER_PREPARE_MAX_S)` seconds from `stat` to `prepared`, then the existing 10 s for `ready`. `SYSTEMAPI_XFER_PREPARE_MAX_S` defaults to 55 and may be set from 1 to 55: the prepare lease lives 60 s and is not renewed, and the whole held request must stay under the 100 s origin timeout of a proxied deployment (worst case 10 + 55 + 10 = 75 s, plus the resolve call). At the 100 MiB/s floor that guarantees about 5.3 GiB; a faster disk hashes more inside 55 s. A file that does not finish is `prepare_timeout`. Later option, not v1: `POST /api/v1/xfer/grant` with `dir:"get"` answers `202 {grant_id, state:"preparing"}` and the client polls `GET /api/v1/xfer/<grant_id>` with the same credential every 2 s until it gets the §3.3 body or an error; the prepare lease is then renewed every 30 s like a start lease, and the cap rises to `SYSTEMAPI_XFER_MAX_SECONDS`. That is what unlocks files beyond a minute of hashing.

3. The sending process re-checks identity, not content. The brief asked for a full re-hash before send; that would double the I/O and the held time for every get, and `recvAgentRun` does it today before `ready`, which a 10 s ready timeout cannot cover past about 1 GiB. Instead the prepare helper reports a stat tuple (`dev`, `ino`, `size`, `mtime_ns`, `ctime_ns`), the agent carries it into the send grant line as `stat`, and the sender refuses `changed` if `fstat` of the file it opened differs in any field. `ctime` cannot be set by an unprivileged user, so an in-place rewrite after prepare changes it. Content is guaranteed by the receiver, which is the client: it hashes every byte and refuses to publish on mismatch. A change during the send is caught there, as `hash_mismatch`. The full re-hash stays available behind `integrity=reread` (design §3.6) for a later policy knob.

4. The start lease is the existing 18-line payload with line 4 `get`, line 7 and 8 the prepared size and hash, line 9 `0` (overwrite is a host-side write flag; a get never writes on the host). The client sends `overwrite:false` for get; `--force` is a local choice only and never reaches the server. The server refuses `dir:"get"` with `overwrite:true` as `bad_request`.

5. Peer mode for get mirrors put. In `listen` the agent's sender binds its pool port and reports it in `ready`; the client dials it; the sender pins the client after the client's first authentic PING. The direct allow list keeps its meaning (the address the client is told to send to is checked), and the client behind NAT needs nothing published. The alternative, the client listening and the agent dialing it, needs a client-reachable port and turns the agent into something the server aims at an address the client chose, which is the exact third-party risk the allow list exists for. Engine roles: no change. The receiver is the dialer and sends the first PING (`engine.go` Pump); the listening sender's own PINGs are queued and flushed at pin (`udp.go`), and `maybeRePing` covers PINGs that went out before the peer existed. In `dial:` both sides dial the relay, unchanged; the agent's sender arrives first, and the relay's one-datagram hold plus `maybeRePing` covers the gap.

6. One helper binary entry, three modes on `recv`: `recv --ctl-fd 3 --event-fd 4` (put or get, chosen by the grant line's `dir`, which the agent copied from the verified lease), `recv --prepare --ctl-fd 3 --event-fd 4`, `recv --sweep [--report] --ctl-fd 3 [--event-fd 4]`. A separate `send` subcommand would duplicate the fd protocol, the supervisor, and the lease-deadline enforcement for no gain; the code path already branches on `dir`. The name `recv` is historical; the README says the agent entry is direction-neutral.

7. The client reports the get result: `POST /api/v1/xfer/<grant_id>/result`, accepted only from the grant's actor with the same credential kind and key id that the grant stored in `g.auth`. It is a second row beside the agent's, never a replacement. The server closes the grant (timers, renewals, cap slot after the window) on whichever result arrives first and keeps a closed entry for the other until the 90 s tombstone window passes. Repeats are idempotent per grant id: the first accepted body wins, a repeat answers 200 with no new row.

8. Policy, budgets, and size. `xfer:get` is already checked as `file:read` with a read policy root (`router.js` near line 582). The check, the xfer rate budget, and the two-live cap all run before `xfer_prepare` is sent, so prepare spends the budget and holds a cap slot. The size cap is enforced twice: the prepare line carries `max_bytes` (`min(SYSTEMAPI_XFER_MAX_BYTES, tenant cap)`), and the helper refuses `too_large` right after `fstat`, before hashing; the server refuses again on `stat`.

9. Zero-length files are allowed: size 0, hash `e3b0c442...b855`, `FIN` with offset 0 and `DONE` (PROTOCOL.md §4.3). The client creates and publishes an empty file.

## Frames and payloads

Prepare lease payload, 7 lines joined by `\n`, no trailing newline, signed as `"<action>\n<payload>"` in `systemapi-lease-v1`, action `xfer` or `xfer_root`:

1. `grant_id`, `^xfr_[A-Za-z0-9_-]{8,64}$`
2. `deadline_unix`, issue plus 60
3. `prepare`
4. `get`
5. `root`, absolute
6. `path`, relative, FILE §5.1 shape
7. `max_bytes`, decimal, 0 to 2^53-1

A prepare lease cannot verify as a start lease (line count and phase), and a start lease cannot verify as a prepare lease. A shared golden vector `docs/golden-xfer-prepare-v1.txt` is copied byte for byte into the Node and agent tests.

Start lease: the 18-line payload unchanged, with `get` on line 4, overwrite `0`, size and sha256 from `prepared`.

Server to agent, `xfer_prepare`: `type`, `grant_id`, `action`, `purpose` (`xfer:get` or `xfer:root`), `dir` (`get`), `root`, `path`, `max_bytes`, `deadline_unix`, `actor`, `lease`.

Agent to server, `xfer_status` payloads added for prepare: `{"status":"stat","size":<n>}`, then `{"status":"prepared","size":<n>,"sha256":"<hex>"}`, or `{"error":"<code>"}` with code one of `not_found`, `not_a_file`, `symlink_refused`, `bad_path`, `too_large`, `io`, `root_denied`, `pty_user_unset`, `root_unavailable`, `cap_reached`, `lease_required`, `internal`. The stat tuple is never sent to the server; it stays in the agent.

Server to agent, `xfer_grant` for get: the put frame unchanged, `dir:"get"`, `overwrite:false`, sent only after `prepared`, with the same `grant_id`. The agent requires a prepared entry for that grant id with the same root, path, size, and hash, or refuses `changed`.

Agent to prepare helper, fd 3, one line, unknown fields refused, 64 KiB cap: `{"v":1,"op":"prepare","grant_id","root","path","max_bytes","deadline_unix"}`. Later lines: `{"op":"cancel","reason"}`; EOF is cancel.

Prepare helper to agent, fd 4: `{"ev":"stat","size":<n>}`, then `{"ev":"prepared","size":<n>,"sha256":"<hex>","stat":{"dev","ino","size","mtime_ns","ctime_ns"}}`, or a last `{"ev":"result","status":"aborted","reason":"<code>","committed":false}`. The helper stops at `deadline_unix` itself with `prepare_timeout`.

Agent to sender, fd 3: the existing grant line plus one field, `stat` (the tuple above), required when `dir` is `get` and refused when `dir` is `put`.

Sender to agent, fd 4: `ready` (`udp` when listening), `active` with bytes the receiver has acknowledged as contiguous, then `{"ev":"result","grant_id","transfer_id","status","reason","bytes","sha256","committed":false}`. For a sender, `status:"ok"` means `DONE` arrived with the grant's size and hash; `sha256` is then the grant hash; `committed` is always false.

Agent to server, `xfer_result` for get: as for put, with `committed:false`; the server reads `ok` for a get as "receiver acknowledged".

Client to server, `POST /api/v1/xfer/<grant_id>/result`, body (unknown fields refused, 4 KiB cap): `{"status":"ok"|"hash_mismatch"|"aborted"|"expired"|"io_error","reason":"<ABORT name or local code>","bytes":<n>,"sha256":"<hex, only when committed>","committed":<bool>}`. Answers: 200 `{"recorded":true}`, 403 `forbidden` (another actor or credential), 404 `not_found` (unknown or window closed), 400 `bad_request`.

## Sequence for get

1. Client checks the local destination before asking (`destFile` with `--force`): `exists`, `symlink_refused`, `not_a_file` stop it with nothing sent. It checks again after the grant, because the answer can take a minute.
2. Client resolves the host (`GET /api/v1/hosts/resolve`), as for put.
3. Client `POST /api/v1/xfer/grant` with `dir:"get"`, root, path, no size, no hash, `overwrite:false`. Server checks shape, scope `file:read`, read policy root, capability `xfer_get` (change 18), xfer budget, two-live cap. Writes `xfer_intent` with phase `prepare`, size and hash null. Audit failure is `internal` and nothing is pushed.
4. Server signs the prepare lease and sends `xfer_prepare`; arms 10 s for `stat`.
5. Agent verifies the lease (rebuilt from the frame), checks the 4-child cap, identity, and root as for put, records `{grant_id, dir:"get", phase:"prepare"}`, and spawns the prepare helper. Any refusal is `xfer_status {error}`; the server ends the grant `aborted` with that code and answers the client with it.
6. Helper opens root and file (`OpenRoot`, `OpenRegular`: openat2 with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS` on Linux, the `O_NOFOLLOW` walk on Darwin), refuses a non-regular file, `fstat`s, refuses `size > max_bytes` as `too_large`, emits `stat`, hashes, emits `prepared`, exits.
7. Agent forwards `stat`; server checks size against `SYSTEMAPI_XFER_MAX_BYTES` (refusal: `xfer_cancel`, client `too_large` 413) and re-arms the hash timer. On timer expiry: `xfer_cancel`, end `aborted` reason `prepare_timeout`, client 504 `prepare_timeout`. The agent's cancel closes fd 3 and the helper exits.
8. Agent keeps `{size, sha256, stat}` for the grant id (memory only, 60 s) and forwards `prepared`. Server checks size again, stores size and hash on `g`, writes nothing new to the audit (the result row will carry them), signs the 18-line start lease, pushes `xfer_grant`, arms 10 s for `ready`.
9. Agent verifies the start lease, matches it to the prepared entry, spawns `recv --ctl-fd 3 --event-fd 4` as the identity with the grant line plus `stat`. Sender opens the file, compares `fstat` to the tuple (`changed`), binds or dials, emits `ready`.
10. Server answers the client with the §3.3 body: purpose `xfer:get`, size and sha256 from prepare, `peer.udp` from `ready` (direct, after the allow list) or the relay.
11. Client checks the response: host, purpose, root, path, overwrite false, bounds; adopts size and hash. It refuses `size` above its local cap (`--max-bytes`, default 256 GiB) as `too_large`. With `--force` and an existing regular destination whose size and SHA-256 already equal the grant's, it does not transfer: it posts `{status:"ok",reason:"unchanged",committed:false,bytes:0}` and prints the three lines. The sender idles out and reports `aborted idle`, which the audit shows beside the client row. Without `--force` an existing destination was already refused in step 1. It creates the temp, dials `peer.udp`, runs the receiver.
12. Receiver verifies the hash over the received bytes, commits (fsync, parent fsync, rename), sends `DONE`. On mismatch it sends `ABORT hash_mismatch`, removes the temp, and the destination is untouched.
13. Client posts its result (5 s budget, two retries on network error), then prints the three lines. A failed post does not change the exit status of a committed file; it writes one diag line on stderr when `--diag` is set.
14. Sender sees `DONE` with the right size and hash, sets `CLOSE_ACK`, emits `result ok`. Agent sends `xfer_result`, removes the record.
15. Server: first result closes the grant (row written, timers cleared), second result writes its own row until the 90 s window passes.

Failure handling: cancel from the client (Ctrl-C) sends one `ABORT cancelled` and posts `aborted cancelled`; the sender stops, agent result `aborted cancelled`. Cancel from the server (`xfer_cancel`) stops the sender; the client sees `ABORT cancelled` or idles out and posts `aborted`. Agent restart mid-send: the sender exits on fd 3 EOF or `Pdeathsig`; on start the agent finds a `dir:"get"` record, runs no sweep (a sender created nothing), and reports `aborted agent_restart committed:false` inside the window; the client independently reports what it saw. Agent restart during prepare: the record has `phase:"prepare"`, the server's hash timer fires, `prepare_timeout`.

## Changes per repo

In dependency order. Every item lands with its tests in the same change.

Design and contract:

1. sahxfer `docs/design.md` §3.2 (`overwrite` is false for get), §3.4 (prepare payload, stat tuple instead of re-hash), §3.6 and §2 (client result route), §15 (get shipped). `PROTOCOL.md` agent-mode section: `--prepare`, the `stat` field, sender result semantics. New `docs/golden-xfer-prepare-v1.txt`.
2. systemapi `playground/xfer.js` header: the new frames; `docs/sah-suite.md`.

sahxfer:

3. `internal/grant/lease.go`: `PreparePayload(grantID, deadline, root, path, maxBytes)` and its golden test.
4. `internal/grant/agent.go`: `AgentGrant.Stat` (dev, ino, size, mtime_ns, ctime_ns), required when `Dir` is get, refused for put; a `PrepareLine` decoder with unknown fields refused.
5. `internal/cli/agent.go`: `recvPrepare` (decision 1, events `stat`, `prepared`, `result`; deadline enforced locally as `prepare_timeout`); in recvAgentRun's sender branch replace the size check and re-hash with the stat-tuple compare (`changed`); in `outcome` add a sender branch: err nil and not a receiver is `ok`, reason empty; set `sha256` to the grant hash on a sender `ok`.
6. `internal/cli/fd_unix.go` or a new `stat_unix.go` (+ `stat_other.go`): `statTuple(*os.File)` from `Fstat`, nanosecond times on Linux and Darwin.
7. `internal/cli/cli.go` cmdRecv flag parsing: `--prepare` requires `--ctl-fd` and `--event-fd` and refuses `--sweep`, `--grant`, `--listen`, `--to`, `--root`.
8. `internal/cli/xfer.go` urlGet: pre-check `destFile` before the grant; request `Overwrite:false` and use `o.overwrite` locally; `--max-bytes`; the unchanged-file shortcut; post the result through the control client on every outcome after a grant was issued.
9. `internal/control/client.go`: `Result(ctx, grantID, Result)` posting to `/api/v1/xfer/<grant_id>/result` with the same credential, grant id checked against the regex before it enters the URL; `allowErr` gains `prepare_timeout`; `decodeGrant` requires `overwrite` false when `req.Dir` is get.
10. `README.md`: `get` usage, exit codes, the error list additions (`changed`, `not_a_file`, `too_large`, `prepare_timeout`).

systemapi server:

11. `controlplane/lease.js`: `xferPreparePayload` with its own phase check (`prepare` only), golden vector.
12. `playground/xfer.js`: lift the `dir !== 'put'` refusal behind capability `xfer_get`; `overwrite:true` with get is `bad_request`; the prepare state machine (`stat` timer, hash timer, `SYSTEMAPI_XFER_PREPARE_MAX_S` 1..55 default 55, `prepare_timeout` 504 in `AGENT_ERRORS`, `not_found` already there); size checked on `stat` and on `prepared`; sign the start lease after `prepared`; `end()` becomes `close()` plus a closed entry `{got:{agent,client}}` that stays until the tombstone timer and counts against the two-live cap only while the other result is pending; `recordClient(grantId, principal, body)`.
13. `controlplane/router.js`: `POST /api/v1/xfer/:grant_id/result`, authenticate, grant id regex, actor and `g.auth` kind and key id equal, body checked, `fleet.xfer.recordClient`; no ticket budget, idempotent; audit action `xfer_client_result`.
14. `tests/xfer.test.js`: prepare vector and every-field tamper; timers; result route auth and idempotency; the four audit combinations below.

systemapi-agent:

15. `lease.go`: `payloadFor` builds the prepare payload when the phase is prepare; `xferPreparePayload` with the shared vector.
16. `xfer.go`: handle `xfer_prepare`; prepared entries keyed by grant id (60 s, memory only); accept `dir:"get"` start grants only with a matching prepared entry; put `stat` in the fd 3 line; forward `stat` and `prepared`; result handling unchanged except `committed:false` is expected for get.
17. `xfer_state.go`: `xferRecord.Dir` and `Phase`; a record without `dir` is put; startup handling skips the sweep for get and reports `aborted agent_restart`.
18. `capabilities.go`: advertise `xfer_get` beside `xfer` when the binary reports `--prepare` support (`sahxfer version` capability line), so an old helper is never handed a get.
19. `xfer_test.go`: fake helper for prepare and send; tamper; prepared mismatch is `changed`; restart with a get record.

## Audit for the four result combinations

Every get has one `xfer_intent` row. Result rows are `xfer_result` (agent) and `xfer_client_result` (client), each with `grant_id`, size, sha256, bytes, status, reason, committed, and duration. The second row to arrive carries `agrees:true|false` against the first.

- Agent ok, client ok committed: two rows, both ok, client `committed:true`, `agrees:true`. The file was delivered.
- Agent ok, client error: two rows, `agrees:false`. The agent's ok means a `DONE` with the right hash arrived under the grant key, which the receiver sends only after it renamed. The audit reads "delivered, client report disagrees": the client lied, or crashed after `DONE` and before its post. No one infers "not delivered".
- Agent error, client ok committed: two rows, `agrees:false`. The client is the receiver and the only party that knows whether its rename happened, so the client row is the commit fact; the usual cause is a lost `DONE` and an agent `idle` or `cancelled`.
- Agent error, client error: two rows, both error, `agrees:true`. Nothing was published.
- Either row missing after 90 s: the missing side is written as `unknown`, never as an error.

## Test plan

Unit (all three repos): prepare payload golden vector in Go and Node; every one of the 7 fields tampered fails verification; a prepare lease presented as a start lease and the reverse fail; `recv --prepare` on a regular file, a directory, a FIFO, a symlink, a path with `..`, a file over `max_bytes`, an empty file; sender stat-tuple mismatch on size, ino, mtime, and ctime is `changed`; sender `outcome` ok; client refuses response overwrite true, size over `--max-bytes`, and an unknown error code; result route auth (other actor 403, same actor other API key 403, repeat 200 no row).

Loopback on macloop (agent with `--xfer-allow-darwin --xfer-udp-listen 127.0.0.1:0`, server `SYSTEMAPI_XFER_PEER_MODE=direct`, a read root under `/Users/ryan/tmp`): get sizes 0, 1, 1152, 1153, 5 MB, and 2 GB. Expect three stdout lines, local hash equal to the host file, no `.sahxfer-*.part` on either side, one intent row and two agreeing ok rows. A 4 GB file within the 55 s hash budget, and a file that exceeds it (throttled read in a test build) giving `prepare_timeout`. Grep logs and audit for the key and route token: zero hits.

linloop (container with the published UDP range, `--xfer-udp-advertise 127.0.0.1`): the same runs, the first through `openat2` and the credential drop. Then relay mode once a relay is admitted: the agent's sender dials first and the client joins seconds later; the transfer must start (the `maybeRePing` path).

Negative cases:

- File changed between prepare and send (append one byte, or `touch` it): sender `changed` before ready, client `changed` 409, rows `aborted`.
- File rewritten in place during the send with the same size: client `hash_mismatch`, local destination untouched, temp gone, rows disagree in reason only, both not committed.
- Host serves different bytes than the lease hash (test sender with a swapped source): client `hash_mismatch`, nothing published.
- Path outside root (`../etc/passwd`, an absolute path, a symlinked component): server `bad_path` or helper `symlink_refused`, no prepare row beyond intent and an `aborted` result.
- Not a regular file (directory, FIFO, socket, device): `not_a_file`, and the FIFO open must not block.
- Oversize: file above `SYSTEMAPI_XFER_MAX_BYTES` gives `too_large` at `stat` with no hash work; file above the client `--max-bytes` gives a local `too_large` and an `aborted` client row.
- Cancel from the client mid-send, cancel from the server (revoke `file:read`) mid-send and mid-prepare.
- Agent restart mid-send (TERM and KILL) and mid-prepare.
- Actor without `file:read`, or with a write-only policy root: 403 before any `xfer_prepare` (the hash oracle test: the agent log shows no prepare).
- Third live get for one actor: `cap_reached`; a held prepare counts.

## Threats

- A hostile host serving a different file than the lease hash: the client hashes every received byte and publishes only on a match; on mismatch it aborts `hash_mismatch`, removes the temp, leaves the destination unchanged, and posts that result. The host can deny service, not substitute content.
- A client reading outside policy: the server checks `file:read` and the read policy root before prepare; the agent verifies the signed root and path; the helper opens with `openat2` and `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS` (Darwin: the `O_NOFOLLOW` walk, which is weaker and dev-only) as the identity user, so the kernel also enforces that user's permissions.
- Prepare as a hash oracle: prepare runs only after the same authority a read needs, spends the xfer budget and a cap slot, and is audited with an intent row; an actor learns a hash only of a file it may read in full anyway.
- Prepare as a probe of existence or type: the error codes (`not_found`, `not_a_file`) are the same an actor with read authority gets from the file channel; nothing more.
- A forged client result: only the grant's actor with the same credential is accepted, and it never replaces the agent's row.
- The client result route as a write amplifier: one row per grant id, a 4 KiB body cap, and no row after the window.
- A stale prepared entry reused for a different start: the agent requires grant id, root, path, size, and hash to match, and drops the entry after 60 s.
- Not defended, stated so no one assumes it: the identity user can forge `stat`, `prepared`, and result events from its own helper; that user can already read the file. A file changed and restored with the same ctime by root is not detected before send; the client hash still is. Darwin's walk is not `openat2`.

## Open questions for the owner

1. Is the production control plane behind a proxy with a 100 s origin timeout (a Cloudflare tunnel answers 524 at 100 s)? If not, `SYSTEMAPI_XFER_PREPARE_MAX_S` can go higher in v1 and the 202 and poll option can wait longer.
2. Should a get of a file larger than about 5 GiB be refused outright until the 202 and poll option lands, or attempted and allowed to fail with `prepare_timeout` on slow disks? This plan attempts it.
