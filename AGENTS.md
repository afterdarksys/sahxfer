# AGENTS.md

sahxfer is a bulk file-copy protocol. SAH authorizes a grant. The bytes move on a separate UDP data plane. The spec is `docs/design.md`. It is not wired and it is not in `~/development/systemapi.io/docs/sah-suite.md`.

## Do this

1. Read `docs/design.md` before changing framing, grants, congestion, or the QUIC modes.
2. Keep file bytes off the SystemAPI WebSocket. That channel stays the grant and the audit.
3. A change to crypto, the grant, path checks, or the relay includes negative tests: tampered tag, expired grant, wrong host, wrong purpose, path escape, symlink, hash mismatch, replay, second 4-tuple. Done when those tests fail closed.

## Rules

- Login stays `sahconnect login`. Reuse the device-login bearer or `X-API-Key` in a header. Do not add a second token file.
- TLS to SystemAPI is 1.3 with the system CA pool. No `InsecureSkipVerify`.
- The grant key and the route token come from `crypto/rand`. They travel only inside that TLS session and the agent's existing authenticated channel. They are never a query parameter or a UDP field that is logged. The HTTP path keeps them in memory and wipes them. The only disk copy is an explicit `sahxfer grant` bootstrap file: mode 0600, `O_NOFOLLOW`, operator-supplied path, never the sahconnect token file and never a cache the HTTP client writes.
- Compare the route token with SHA-256 of both sides, then `subtle.ConstantTimeCompare`. AEAD failure uses the library open, which is constant-time. Do not compare tags with `==`.
- Data-plane cipher is ChaCha20-Poly1305. Nonce is direction plus sequence. No ECB, no CBC, no `crypto=off`, no 0-RTT.
- Unknown version is dropped before AEAD. Unknown type, unknown flag bit, a flag on the wrong type, length mismatch, or offset wrap: drop if the packet did not open, otherwise abort the grant. Do not skip the field and continue.
- The agent process that owns the UDP socket does not hold the grant key and does not see plaintext. A dropped-privilege helper decrypts and writes, as `pty_user`, through `openat2` with `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`. Same path rules as the file protocol.
- Write to a temp file, fsync, then rename. A hash mismatch deletes the temp file and leaves the target untouched.
- The relay forwards sealed datagrams. It does not get the grant key. v1 has no decrypting bridge.
- QUIC datagram mode turns sahxfer pacing off. QUIC is the only congestion controller on that path. Do not stack both.
- Do not log the bearer, the ticket, the grant key, the route token, or file bytes. A grant id may be logged.
- Do not edit `systemapi.io` from this repo. The grant API is specified here and lands there only as its own change, with the suite Wired join updated in that same change.
- No AI attribution in commits.

## Next

`docs/design.md`. Module path is `github.com/afterdarksys/sahxfer`. Congestion in code is pace-bbr. Do not describe the Darwin path walk as `openat2`, and do not add an io_uring file until a Linux build actually submits it.
