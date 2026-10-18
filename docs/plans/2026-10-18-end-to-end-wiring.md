# sahxfer end-to-end wiring plan

Status: plan, 2026-10-18. Nothing here is implemented. It covers the three repositories that must change together: sahxfer (this repo), the systemapi server (worktree `/Users/ryan/development/systemapi.io-xfer`, branch `feat/suite-contract-xfer`, commit 8404cb1), and `systemapi-agent/` in that worktree. It follows `docs/design.md`. Where this plan changes a design rule, the design edit lands first, as the design asks.

## What exists today

sahxfer:

- `put --url` and `get --url` call `GET /api/v1/hosts/resolve`, then `POST /api/v1/xfer/grant` (`internal/control/client.go`). `decodeGrant` checks host, purpose, root, path, size, hash, overwrite, profile, transport, AEAD, idle and max bounds, byte cap, expiry, transfer id shape, and canonical base64 of the key and route token.
- `recv` reads a bootstrap grant file (`--grant`), binds with `--listen` or dials with `--to`, writes the temp file through `safeio`, and prints three lines. It does not verify any lease and does not change uid (`internal/cli/xfer.go` cmdRecv).
- `internal/grant/lease.go` has `Sign` and `Verify` over a bare Ed25519 signature of the 8-line payload. Nothing in the CLI calls them.
- `relay` admits grants only from `--grant` files (`internal/cli/cli.go` cmdRelay). A test already runs put through a relay to a `recv --to relay` (`internal/cli/cli_test.go`, the relay test near line 495). The receiver engine sends a PING first (`internal/engine/engine.go` Pump), so a receiver behind NAT can pin itself at a relay.
- The control client accepts only `https` (`parseBase`). sahsync accepts `http` to a loopback literal (`sahsync/internal/client/client.go`).

systemapi server:

- `POST /api/v1/xfer/grant` (`controlplane/router.js` near line 577, `playground/xfer.js`). Put over udp only. `peer.udp` is `SYSTEMAPI_XFER_PEER_UDP`, unset is `agent_unsupported`. It writes `xfer_intent`, pushes `xfer_grant` with a `systemapi-lease-v1` lease over `sha256("xfer\n" + 8-line payload)`, waits up to 10 s for `xfer_status ready`, returns the §3.3 JSON, renews every 30 s, cancels on 60 s without `active`, idle, max, lost scope, or client hang-up, tombstones for 90 s, and writes `xfer_result` from the agent's frame.
- `expires_at` in the response is issue plus 60 s, the first-packet deadline (design §3.3). The rate check reuses `ticketAllowed` with the file purpose, so `xfer:put` spends the `terminal` budget keyed by actor and host (`router.js` ticketBudget, default 20 per minute), the same counter as `terminal:open`, `file:read`, and `file:write` tickets. `xfer:root` spends the `privileged` budget.

systemapi-agent:

- No xfer code. `lease.go` `knownAction` and `payloadFor` do not know `xfer` or `xfer_root`, so `authorizeCommand` would refuse them as `bad_action` today.
- The file channel is the pattern to copy: `file.go` verifies the lease by rebuilding the payload from what it will open, keeps the lease expiry in the parent and ends the session when it lapses, and `file_spawn_linux.go` starts the helper with `SysProcAttr.Credential`, `Setsid`, `Pdeathsig SIGKILL`, empty env, `Dir "/"`. `file_spawn_other.go` refuses on non-Linux. Sessions live on `channelConn` and end when the connection closes (`tcp.go` close).
- Capabilities register through `registerCapability` (`capabilities.go`).

Two defects found while reading, both in sahxfer, both blockers for a real transfer:

- `Grant.RunLimits` caps the hard stop at `Expires` (`internal/grant/grant.go`). The local issuer sets `Expires = now + Max`, but the server sets `expires_at` to the 60 s first-packet deadline. Every HTTP-granted transfer is therefore cut at 60 s with `expired`.
- A listening runner pins the first source address before AEAD (`internal/udp/udp.go`, the `!cfg.Connected` branch). On a reachable listen port, one forged datagram pins the wrong peer and the transfer idles out.

## Decisions

1. The agent verifies the lease envelope. sahxfer does not. The agent already pins the control key, checks host binding, action, expiry and skew, and keeps the nonce replay cache (`lease.go` verifyLease, authorizeCommand). `recv` runs as `pty_user` and would need the pinned key, the host id and a replay cache handed to it, which is a second verifier to keep identical. A compromised agent parent could start `recv` with any grant anyway, so a second check in the child buys nothing. The agent hands `recv` a grant it has already verified, on a pipe. sahxfer keeps only a payload builder with a shared golden test vector, and the bare-signature `Sign` and `Verify` are deleted, so there is one lease format in the suite.

2. The signed payload grows to 18 lines. It binds every field the agent or `recv` acts on, including a hash of the key material. The 8-line form was never verified by any agent, so there is no compatibility step. The agent rebuilds the payload from the frame fields it is about to use, as the file channel does, so a changed field fails as `payload_mismatch`. A renew is rebuilt from the stored grant with only phase and deadline changed, so a renew cannot change a field.

3. `recv` is spawned by the agent as the identity user with the file helper's credential path, and talks over two inherited pipes. Fd 3 carries agent-to-recv JSON lines: the grant, then renew and cancel. Fd 4 carries recv-to-agent JSON lines: ready, progress, result. Never argv, never env, never disk. Stdout keeps its three-line contract. Stderr is one code, logged by the agent. EOF on fd 3 means cancel, which covers Darwin, where there is no Pdeathsig. On Linux the xfer child gets `Pdeathsig SIGTERM`, not SIGKILL, so an agent crash still lets `recv` delete its temp file.

4. The socket stays in `recv`, not in the agent. Design §3.4 allows the parent to own the socket, but the agent already receives the key in `xfer_grant`, so moving the socket to the parent hides nothing, and `recv` already binds and dials. Moving the socket is a later optimisation, not v1.

5. Peer addressing has two modes, chosen by the server. `listen`: `recv` binds an address the agent chooses from its own flags, reports the bound or advertised address in `ready`, and the server returns it as `peer.udp`. The server already waits for `ready` before it answers the client, so no second poll is needed. `dial:<host:port>`: `recv` dials a relay and sends the first packet. `peer_udp` always means "the address the client sends to". Behind NAT with no published port, `listen` cannot work, and that is what the relay is for.

6. Put first. Get is phase 2 (design §15), with the frame defined below and not implemented.

7. The client does not report a result for put. The agent is the receiver and the only party that knows whether the rename happened. A client report would add an authenticated write path that can contradict the agent and would need reconciliation rules. For get (phase 2) the client is the receiver, and `POST /api/v1/xfer/<grant_id>/result` is added then, accepted only from the grant's actor, recorded beside the agent's row, never replacing it. Design §2's arrow from client to SystemAPI is changed to say this.

8. Error codes pass through verbatim from a closed list. Anything outside it is `request_failed`. The list is under "Error codes" below.

9. xfer gets its own rate budget key. `ticketBudget` returns `xfer` for `xfer:put` and `xfer:get` (`SYSTEMAPI_TICKET_RATE_XFER`, default 20 per minute per actor and host). `xfer:root` stays on `privileged`. A scripted put loop must not lock the operator out of the shell or the sahsync session needed to diagnose it. The two-live-grant cap per actor stays, and it counts tombstones for up to 90 s, so the client never retries `cap_reached` by itself. The agent adds its own cap of 4 live xfer children, separate from the 16 file sessions.

10. Darwin is a development target only. The agent advertises `xfer` on Linux when `openat2` works and the sahxfer binary is configured. On Darwin it advertises `xfer` only with `--xfer-allow-darwin`, which logs a warning like `--pty-allow-agent-user` does. sahxfer's Darwin commit moves from check-then-`renameat` to `renameatx_np(RENAME_EXCL)` so `overwrite:false` holds there too.

11. The client accepts `http://` only to a loopback IP literal, the sahsync rule, so the loopback stack at `127.0.0.1:3103` works without a test CA. `localhost` stays refused, because it resolves through the resolver. Every other origin stays https and TLS 1.3.

12. A grant's `expires_at` is the first-packet deadline, as design §3.3 says. The hard stop is issue time plus `max_seconds`. sahxfer's grant gains `FirstBy` (from `expires_at`) and `HardStop` (from `expires_at - expires_in + max_seconds`, clamped to 3600 s after issue). The bootstrap file keeps its fields and gets the same meaning.

## Frames and payloads

Lease payload (design §3.4, replaces the 8-line form). Lines joined by `\n`, no trailing newline, signed as `"<action>\n<payload>"` inside `systemapi-lease-v1`. Builders refuse a control byte or newline in any field.

1. `grant_id`, matching `^xfr_[A-Za-z0-9_-]{8,64}$`
2. `deadline_unix`, the lease deadline, issue plus 60
3. `start` or `renew`
4. `put` or `get`
5. `root`, absolute
6. `path`, relative, FILE §5.1 shape
7. `size`, decimal
8. `sha256`, 64 lowercase hex
9. `overwrite`, `0` or `1`
10. `transfer_id`, 16 lowercase hex, not all zero
11. `expires_unix`, the first-packet deadline
12. `idle_s`, 1 to `max_s`
13. `max_s`, 1 to 3600
14. `byte_cap`, decimal, at least `size`
15. `profile`, `internet` or `dc`
16. `transport`, `udp` in v1
17. `peer`, `listen` or `dial:<host:port>`
18. `material`, hex of `sha256("sahxfer-material-v1\n" || key || route_token)` over the raw 32 and 16 bytes

The server stores the material hash for renewals, not the key. The client cannot check the lease, because it does not pin the control key. It checks the response fields it can compare against what it asked: host id, purpose, root, path, size, sha256, overwrite (already in `decodeGrant`), plus transfer id shape, idle no more than max, max at most 3600, byte cap at least size, profile, transport, AEAD, and canonical key and token lengths (also already there).

Server to agent, `xfer_grant` (changes from today's frame: `peer_udp` is replaced by `peer`, the rest is unchanged): `type`, `grant_id`, `transfer_id`, `action` (`xfer` or `xfer_root`), `purpose`, `dir`, `root`, `path`, `size`, `sha256`, `overwrite`, `profile`, `transport`, `peer`, `aead`, `key`, `route_token`, `expires_unix`, `deadline_unix`, `idle_s`, `max_s`, `byte_cap`, `actor`, `lease`.

Server to agent, `xfer_renew`: `grant_id`, `deadline_unix`, `lease` (exists today).

Server to agent, `xfer_cancel`: `grant_id`, `reason` (exists today).

Agent to server, `xfer_status`, `payload` one of:

- `{"status":"ready","udp":"<host:port>"}`. `udp` is required when `peer` is `listen`, and absent for `dial:`.
- `{"status":"active","bytes":<n>}`, sent on the first authentic packet, then at most every 5 s, so the server's 60 s first-packet and idle timers see progress.
- `{"error":"<code>"}`, before ready a refusal, after ready terminal.

Agent to server, `xfer_result`, `payload`: `status` (`ok`, `hash_mismatch`, `aborted`, `expired`, `io_error`, the existing set), `reason` (an ABORT name from PROTOCOL.md §4.4, or `stopped`, `agent_restart`), `bytes`, `sha256` (the committed hash, only when committed), `committed` (bool). The server records `reason` after checking it against that list.

Agent to recv, fd 3, one JSON object per line. The first line is the grant: `v` (1), `grant_id`, `transfer_id`, `purpose`, `dir`, `root`, `path`, `size`, `sha256`, `overwrite`, `profile`, `transport`, `aead`, `key`, `route_token`, `expires_unix`, `deadline_unix`, `idle_s`, `max_s`, `byte_cap`, `peer` (`listen:<bind addr>` with the address the agent picked, or `dial:<host:port>`). It is decoded with unknown fields refused, a 64 KiB cap, and then the same `Grant.Check` the file path uses. The buffer is wiped. Later lines: `{"op":"renew","deadline_unix":<n>}` (a deadline may only move forward) and `{"op":"cancel","reason":"<code>"}`. EOF is cancel with reason `stopped`.

recv to agent, fd 4, one JSON object per line: `{"ev":"ready","udp":"<bound or advertised addr>"}`, `{"ev":"active","bytes":<n>}` (at most once a second), `{"ev":"result","grant_id","transfer_id","status","reason","bytes","sha256","committed"}`. The result is the last line, then `recv` exits. Never the key or the token.

Agent to server, phase 2 get, not built: server sends `xfer_prepare` {`grant_id`, `action`, `purpose`, `dir:"get"`, `root`, `path`, `lease`}, with a 7-line prepare payload (grant id, deadline, `prepare`, `get`, root, path, and `-` for size). The agent spawns `recv` in stat mode as the identity. It opens the file with `openat2`, refuses a non-regular file, and hashes it. The agent answers `xfer_status {"status":"prepared","size":<n>,"sha256":"<hex>"}`. The server then signs the 18-line start lease with that size and hash and continues as for put, with the agent as sender. The sending `recv` re-stats and re-hashes and refuses with `changed`. The 10 s ready timeout does not fit a large hash: phase 2 needs a prepare timeout proportional to size, and either a held HTTP request or a 202 and a poll. That choice is made in phase 2.

## Sequence for put

1. Client hashes the local file (`safeio.OpenRead`, `hashFile`). Failure is a local code and nothing is sent.
2. Client `GET /api/v1/hosts/resolve?name=`. `404 not_found`, `409 ambiguous`, `400 invalid_name` stop it. `offline` is `agent_offline`.
3. Client `POST /api/v1/xfer/grant`. The server checks shape (400), scope (403), host (404), tenant scope, policy root, capability, the xfer rate budget (429 `rate_limited`), and the two-live cap (429 `cap_reached`). It writes `xfer_intent`. On an audit failure the answer is `internal` and nothing is pushed.
4. The server picks the peer mode: `listen` when `SYSTEMAPI_XFER_PEER_MODE=direct`, else `dial:` plus `SYSTEMAPI_XFER_PEER_UDP`. Unset relay in relay mode is `agent_unsupported`. It signs the 18-line start lease and pushes `xfer_grant`.
5. The agent rebuilds the payload from the frame and calls `authorizeCommand` with action `xfer` or `xfer_root`. Failure is `xfer_status {"error":"lease_required"}`, the server ends the grant `aborted`, and the client gets `internal`. The agent then checks: `transport` is udp, `expires_unix` is in the future, `max_s` is at most 3600, `idle_s` is at most `max_s`, byte cap is at least size, the 4-child cap (`cap_reached`), identity (`resolveFileIdentity`: `pty_user_unset`, `root_unavailable`), and the root (`checkSessionRoot`: `root_denied` for `/` or the state directory). Each failure is a refusal before ready.
6. The agent records `{grant_id, root, path, identity}` in its state directory, then spawns `sahxfer recv --ctl-fd 3 --event-fd 4` with the credential, writes the grant line, and closes nothing else. A spawn failure is `internal`, and the record is removed.
7. `recv` decodes and checks the grant, opens the root and creates `.sahxfer-<grant_id>.part` (`exists`, `symlink_refused`, `not_a_file`, `bad_path`, `no_space` reach the agent as a result with `committed:false`). It binds (`listen:`) or dials (`dial:`). A failure is a `result` event, and the agent turns a result before ready into `xfer_status {"error":code}`.
8. `recv` emits `ready` with the address. The agent sends `xfer_status ready` with `udp` in listen mode. A ready without `udp` in listen mode is refused by the server as `internal`.
9. The server sets `peer.udp`, either the reported address (after `peerAddress` and, in direct mode, a check that the IP is in `SYSTEMAPI_XFER_DIRECT_ALLOW`, a CIDR list, default loopback only) or the relay. It answers the client and arms renew, max and the first-packet timer. If the client hung up, the server sends `xfer_cancel`.
10. The client checks the response (`decodeGrant`), dials `peer.udp`, and runs the sender until `DONE` checks out. Failures are the ABORT names. Cancel, Ctrl-C included, sends one `ABORT cancelled` before exit (new, step "udp" below).
11. `recv` sends `active` on the first authentic packet and then at most every second. The agent forwards at most every 5 s. A silent receiver lets the server cancel after 60 s or after `idle_s`.
12. Every 30 s the server re-checks authority and sends `xfer_renew`. The agent verifies the renew payload rebuilt from the stored grant and writes `{"op":"renew"}` to fd 3. A refused renew is logged and ignored. When the lease lapses, the agent writes `cancel stopped`, waits 2 s, sends SIGTERM, waits 3 s, then SIGKILL.
13. `xfer_cancel` arrives: `cancel` on fd 3. `recv` sends `ABORT cancelled`, deletes the temp, and emits `result`.
14. `recv` commits (fsync temp, fsync parent, `RENAME_NOREPLACE` or `renameatx_np(RENAME_EXCL)` unless overwrite), sends `DONE`, waits for `CLOSE_ACK` or idle, then emits `result` with `committed:true` and `status:"ok"` even if `CLOSE_ACK` never came. The commit is the fact the audit needs.
15. The agent sends `xfer_result`, removes the state record, and reaps the child. If the control connection is down, the result waits in the xfer manager and goes out on the next connection. The server accepts it from any socket of that host until the tombstone closes. Past that the row says `unknown`.
16. The client prints the grant id, the transfer id, and `ok`, after `DONE` checks out. It does not call the server again.

Agent restart mid-transfer: Linux `Pdeathsig SIGTERM` or EOF on fd 3 makes `recv` abort and delete its temp. On start, the agent reads leftover state records and spawns `recv --sweep` per record as that identity, which removes only `.sahxfer-<grant_id>.part` under the root (the name is fixed by the grant id). It then reports `xfer_result {"status":"aborted","reason":"agent_restart","committed":false}` if it reconnects inside the 90 s tombstone. A record whose target already holds the grant's hash is reported `ok`, `committed:true`.

## Changes per repo

In dependency order. Every item lands with its tests in the same change.

Design and contract (first, in both repos together):

1. sahxfer `docs/design.md`: §3.4 18-line payload and the material line; §2 and §3.6 result reporting (agent only for put, client for get in phase 2); §3.3 `expires_at` is first packet and the hard stop is issue plus `max_seconds`; §3.4 the socket stays in the helper in v1; peer modes `listen` and `dial:`. `PROTOCOL.md` §1 to match.
2. systemapi `docs/sah-suite.md` "Partially wired": replace the unsigned-fields and lease-format bullets with a pointer to the new payload; add the frames above to the `playground/xfer.js` header comment.

sahxfer:

3. `internal/grant/lease.go`: delete `Sign`, `Verify`, `parseLease`, `split8`, and add `Payload(g, deadline, phase, peer, material)` that returns the 18-line form and `Material(key, token)`. A golden test vector (fixed inputs, exact string, exact `sha256("xfer\n"+payload)`) is copied byte for byte into `tests/xfer.test.js`.
4. `internal/grant/grant.go`: `FirstBy` and `HardStop`, `RunLimits` uses `HardStop`, the engine `FirstPacket` is `FirstBy - now`. `Issue` and the file reader set both. Test: an HTTP grant with `expires_in` 60 and `max_seconds` 3600 gives a hard stop near 3600 s, not 60.
5. `internal/engine`: `Peer.Committed()`; `Peer.Cancel(now)` that aborts with `cancelled` and queues one ABORT.
6. `internal/udp/udp.go`: a listener pins the first source only after `Peer.Recv` reports an authentic packet (`Recv` returns bool); on ctx done it calls `Cancel`, flushes once, and returns; add `Config.Progress func(delivered uint64)`, called at most once a second.
7. `internal/safeio/open_darwin.go`: `renameExclusive` uses `unix.RenameatxNp(..., RENAME_EXCL)` when overwrite is false.
8. `internal/cli/xfer.go`, new recv mode: `recv --ctl-fd N --event-fd M`, refused with any of `--grant`, `--listen`, `--to`, `--root`. Reads the grant line (decision 3), runs a goroutine on fd 3 for renew, cancel and EOF, enforces the lease deadline itself (abort `expired` at `deadline_unix`, moved only by renew), emits the events, and maps the outcome to the result fields (`committed` from `Peer.Committed`). Add `recv --sweep --ctl-fd N`, which reads `{root, path, grant_id}` and removes only that temp name.
9. `internal/control/client.go`: `parseBase` and `do` accept `http` to a loopback IP literal; replace `allowErr` with the list below.
10. `README.md` and `PROTOCOL.md`: the recv agent mode, and that stdout is unchanged.

systemapi server:

11. `controlplane/lease.js`: `xferPayload` takes the 18 fields and validates each (overwrite boolean, transfer id regex, expires, idle, max, byte cap ranges, profile and transport enums, peer `listen` or `dial:` plus `peerAddress`, material 64 hex). Golden vector test from item 3.
12. `playground/xfer.js`: compute the material hash once and keep it on `g`; sign start and renew with the new payload; `peer` replaces `peer_udp`; `SYSTEMAPI_XFER_PEER_MODE` (`relay` default, `direct`); in direct mode take `udp` from `ready`, check it with `peerAddress` and `SYSTEMAPI_XFER_DIRECT_ALLOW`, and put it in `doc.peer.udp`; accept `reason` and `committed` on `xfer_result`; add to `AGENT_ERRORS`: `pty_user_unset` 503, `root_unavailable` 503, `lease_required` 500 (sent to the client as `internal`), `no_space` 507, `io` 500.
13. `controlplane/router.js`: `ticketBudget` returns `xfer` for `xfer:put` and `xfer:get` and reads `SYSTEMAPI_TICKET_RATE_XFER`. The route passes the xfer purpose, not the file purpose, to `ticketAllowed`.
14. `tests/xfer.test.js`: v2 payload, every field tamper fails `verifyLease`, direct mode ready with and without `udp`, an address outside the allow list refused, rate budget separation, result `reason` passthrough.

systemapi-agent:

15. `lease.go`: `xferAction` (`xfer`, `xfer_root`) in `knownAction` and `payloadFor`; `xferLeasePayload` mirroring item 11, with the golden vector.
16. `xfer.go` (new): an agent-level `xferManager`, not on `channelConn`, so a connection drop does not kill a transfer. It handles `xfer_grant`, `xfer_renew`, `xfer_cancel` (hooked from `channelConn.handle`), the checks of sequence step 5, the 4-child cap, the lease watcher of step 12, event forwarding with the 5 s progress throttle, and a result queue flushed on the next connection.
17. `xfer_spawn_unix.go` (new): `startXferProc(id, exe)`, the same credential path as `startFileHelperProc`, plus `ExtraFiles` for fds 3 and 4, `Setsid`, empty env, `Dir "/"`, `Pdeathsig SIGTERM` on Linux. `xfer_spawn_other.go` refuses on Windows.
18. `xfer_state.go` (new): records in the state directory, mode 0600, written before spawn and removed after the result is sent; the startup sweep of the restart paragraph.
19. `main.go`: `--xfer-bin` (absolute path; refused if group or other writable, or not owned by root or the agent user), `--xfer-udp-listen` (`ip:port` or `ip:lo-hi`; unset means listen mode is refused with `agent_unsupported`), `--xfer-udp-advertise` (`ip`, for a published port behind NAT or Docker), `--xfer-allow-darwin`.
20. `capabilities.go` registration from `xfer.go` `init`: Linux needs `openat2Available()` and `--xfer-bin`; Darwin also needs `--xfer-allow-darwin`.
21. `xfer_test.go`: lease verify and every field tamper, renew cannot change a field, a refusal before spawn for each step 5 check, cancel reaches fd 3, a connection drop keeps the child and the result goes out on reconnect, the restart sweep. Use a fake `recv` built from the test binary, as the file helper tests do.

## Error codes the client accepts

Everything else is `request_failed`. Server and agent lists are from `router.js` (authenticate, requireHost, requireScope, ticketAllowed, resolve), `xfer.js` (parseGrantRequest, grant, AGENT_ERRORS), and `channels.js` policyDecision.

- Auth: `unauthorized`, `bearer_required`, `query_key_rejected`, `forbidden`, `sso_unbound`, `oauth_unavailable`, `registry_unavailable`.
- Request shape: `bad_request` (missing today, and the most common), `bad_purpose`, `bad_root`, `bad_path`, `reserved_name`, `too_large`, `invalid_name`.
- Authority: `scope_denied`, `root_denied`, `not_found`, `ambiguous`.
- Capacity: `rate_limited`, `cap_reached`.
- Host: `agent_offline`, `agent_unsupported`, `pty_user_unset`, `root_unavailable`.
- Target: `exists`, `symlink_refused`, `not_a_file`, `changed`, `no_space`.
- Server: `internal`, `io`.
- Already local in the client and kept: `auth`, `expired`, `mismatch`, `bad_grant`.

`client_gone` (499) is never seen by a client that is still reading, and is not in the list.

## Test plan

Unit, all three repos: the items above. The shared golden payload vector must produce the same string and the same hash in Go (sahxfer and agent) and in Node. A CI check in each repo fails if its copy of the vector changes.

Loopback end to end on macloop (control plane `http://127.0.0.1:3103`, Darwin agent `macloop` running as ryan):

1. Build sahxfer. Start the agent with `--pty-allow-agent-user --xfer-allow-darwin --xfer-bin <absolute path> --xfer-udp-listen 127.0.0.1:0`. Server env: `SYSTEMAPI_XFER_PEER_MODE=direct` (allow list defaults to loopback). File policy for macloop: a write root at a fresh directory under `/Users/ryan/tmp`, not the agent state directory.
2. `sahxfer put --url http://127.0.0.1:3103 --root <root> --api-key <key> ./blob macloop:<root>/in/blob` for sizes 0, 1, 1152, 1153, 5 MB, and 2 GB. Expect three stdout lines, the target hash equal to the source, no `.sahxfer-*.part` left, `xfer_intent` and then `xfer_result` with status `ok`, `committed` true, `bytes` equal to size.
3. A transfer that runs longer than 60 s (2 GB with `SYSTEMAPI_XFER_IDLE_SECONDS` default and a pacing-limited path, or a test-only rate cap in `udp.Config`) must finish. That is the `HardStop` fix.
4. Grep the agent log, the server log, the audit rows, and both stderr streams for the key and the route token. Zero hits.

linloop, after UDP is reachable. Recreate the container with `-p 127.0.0.1:47000-47003:47000-47003/udp` and run the agent with `--xfer-udp-listen 0.0.0.0:47000-47003 --xfer-udp-advertise 127.0.0.1`. Same steps as macloop. This is the first run of the `openat2` path, the credential drop to `--pty-user`, and `Pdeathsig`. Once a relay is admitted by the server, linloop is also the natural relay test, since outbound UDP from the container works without any mapping.

Negative cases, each with the expected outcome:

- Tampered frame (each of the 18 fields changed after signing, one at a time): agent `lease_required`, no child spawned, client `internal`, result row `aborted`.
- Expired lease (`deadline_unix` in the past, and a lease `expires_unix` older than 30 s skew): `lease_required`. A renew that never comes: the child gets `cancel stopped` at lease lapse, temp gone, result `aborted` reason `stopped`.
- Wrong key: lease signed by another Ed25519 key, `bad_signature`. Also client data sealed with another grant key: 32 failed opens abort `auth`, temp gone.
- Oversize: request size above `SYSTEMAPI_XFER_MAX_BYTES`, 413 `too_large`. Sender pushes past `byte_cap`, `byte_cap` abort. A fd 3 grant line over 64 KiB, `recv` refuses, `internal`.
- Overwrite without flag: target exists, `overwrite:false`. `recv` refuses before ready with `exists`, target bytes unchanged. Then a race: create the target after ready. The commit fails `exists` through `RENAME_NOREPLACE` (Linux) or `RENAME_EXCL` (Darwin), and the result is `committed:false`.
- Forged `overwrite:true` in the frame with a lease that signed `0`: `payload_mismatch`.
- Cancel mid-transfer: client Ctrl-C, the receiver sees `ABORT cancelled` within one RTT. Server `xfer_cancel` (revoke the operator's scope): the client sees `cancelled` or `idle`, the temp is gone, the row is `aborted` reason `cancelled`.
- Agent restart mid-transfer: kill -TERM the agent, then restart. `recv` exits and the temp is gone. Kill -KILL the agent, then restart. On Linux `Pdeathsig` and on Darwin fd 3 EOF stop `recv`. The sweep removes any leftover temp. The row is `aborted` reason `agent_restart` if the agent reconnects within 90 s, else `unknown`.
- Connection drop without restart: the transfer finishes inside the current lease (up to 60 s), and the result arrives on the new socket.
- Forged first datagram to a listen port before the client's: the transfer still completes (the pin-after-auth fix).
- Third grant for one actor: `cap_reached`. 21 grants in a minute: `rate_limited`, and a `terminal:open` ticket for the same host still succeeds.
- `http://localhost:3103` and `http://192.0.2.1`: refused locally, nothing sent.

## Threats

What each layer refuses.

- Client: a response that differs from the request in host, purpose, root, path, size, hash, or overwrite; a non-canonical key or token; idle above max, max above 3600, byte cap below size; plain http to anything but a loopback literal; redirects; a credential in a query string; printing the key, the token, or the bearer.
- Server: missing scope or policy root; a third live grant; an over-budget actor; a grant with no durable intent row; an agent without `xfer`; a direct-mode address outside the allow list (so an agent cannot aim a client at a third party); renewal after authority is withdrawn. It never logs or audits the key or the token, and signs the material hash, not the material.
- Agent: any lease that does not verify for this host, this action, and every field it will use; a replayed nonce; a renew that would change anything but the deadline; `xfer_root` on a non-root agent; any xfer on a non-root agent without `--pty-allow-agent-user`; root `/` or a root holding the state directory; more than 4 children; a `--xfer-bin` that the identity user could replace. The child runs with empty env, no credentials of the agent, and only fds 0, 1, 2, 3, 4.
- recv: a grant line with unknown fields or over 64 KiB; any `Grant.Check` failure; symlinks and `..` at open (`openat2`, or the Darwin `O_NOFOLLOW` walk); an existing target without overwrite; a datagram that fails route token or AEAD (dropped, counted, 32 abort); a source other than the pinned authentic peer; work past the lease deadline it was given, even if the agent does not stop it.
- Relay (future): no key, a third source, the 32nd token mismatch, past byte cap.
- Not defended, stated so no one assumes it: the identity user can read the key from its own `recv` process. That user may already write the target. A hostile root on the host. Darwin's walk is not `openat2`. A missing `xfer_result` after the tombstone is `unknown`, not "unchanged".

## Relay deployment needs, without designing the relay

- A relay host with a public UDP port that is not one of the frozen hosts (apps, apps2, stack, ns*, relay-*). A mutation there would need a runbook.
- The `sahxfer relay` binary from this repo, with a new admission source. Today it reads grants only from `--grant` files. The server would push `{transfer_id, route_token, byte_cap, expires}` to it on an authenticated channel, never the key. That channel is the relay design.
- `SYSTEMAPI_XFER_PEER_MODE=relay` and `SYSTEMAPI_XFER_PEER_UDP=<relay host:port>` on the server.
- Agents use `dial:` mode, which needs no listen flags. Both peers send outbound to the relay.

## Open questions for the owner

1. Where the relay runs. It needs a public UDP port, its bandwidth is every transfer's bandwidth, and DartNode egress filtering on this fleet has bitten before. Candidates are a non-frozen fleet host or a new small VM. This plan does not pick one.
2. Whether direct mode is ever allowed in production. This plan defaults to relay and limits direct to `SYSTEMAPI_XFER_DIRECT_ALLOW` (loopback by default), which is what the macloop and linloop tests need.
3. How the sahxfer binary reaches hosts: shipped inside the agent package at a fixed root-owned path, or installed separately and named by `--xfer-bin`. This decides whether `--xfer-bin` is a flag or a constant.
