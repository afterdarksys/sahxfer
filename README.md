# sahxfer

Bulk file copy that uses SAH to decide whether a transfer may happen, then moves the bytes on its own UDP plane.

**sah** means Service Automation Hub. The hub encompasses the platform and the suite of utilities. `adssh` stays the development name of the shell. This directory is not a rename of `sahsync`, `sahlink`, or `sahconnect`.

Module `github.com/afterdarksys/sahxfer`. The command is `cmd/sahxfer`.

```
sahxfer put --url https://sah.example --root /srv/app --api-key <key> ./app.tar.gz web1:/srv/app/releases/app.tar.gz
sahxfer get --url https://sah.example --root /srv/app --token <token> web1:/srv/app/releases/app.tar.gz ./
```

`--token` is the sahconnect device-login bearer. The client sends it as `Authorization` only when the token is bound to that origin. `--api-key` is sent as `X-API-Key`. Pass one of them. The same two commands without `--url` and `--root` write `bad_root` on stderr and exit 1.

`put` and `get` can run from a local grant file (`--grant`) instead of `--url`. `get` is the same grant with the peers swapped. `recv` is the host side of that file. `relay` forwards sealed datagrams and does not have the key. `grant` writes a bootstrap grant file, mode 0600. That file is the only disk copy of the key. The HTTP path keeps the key and the route token in memory.

A finished command writes three lines to stdout: the grant id, the transfer id as 16 hex digits, and `ok`. Stderr is a code. The process does not print the bearer, the API key, the grant key, the route token, or file bytes.

`recv --ctl-fd 3 --event-fd 4` is the mode the host agent spawns, as the host user, after it has verified the lease. It is refused with `--grant`, `--listen`, `--to`, or `--root`. Fd 3 carries one JSON grant line (unknown fields refused, 64 KiB cap), then `renew` and `cancel` lines; EOF on fd 3 is cancel. Fd 4 carries `ready`, `active`, and one final `result` line, never the key or the route token. `recv` stops itself at the lease deadline it was given unless a renew moves it forward. Stdout and stderr keep the contract above. `recv --sweep --ctl-fd 3` reads `{root, path, grant_id}` and removes only that grant's `.sahxfer-<grant_id>.part`. `PROTOCOL.md` §1.1 has the lines.

`--diag` on `put`, `get`, and `recv` adds `diag ` lines on stderr: the granted socket buffers when the socket opens (`diag rcvbuf=<n> sndbuf=<n>`), one `diag warn` line if the receive buffer is smaller than the arrival rate times `max(RTprop, 5 ms)`, and at most one `diag pace` line per second on the UDP sender with state, bandwidth estimate, flight bytes, window cap, delivered prefix, and smoothed RTT. Without it stderr is only the code.

`put --pipeline-source` enables experimental asynchronous source read-ahead.
One worker reads the next block while the engine processes the current block,
using at most 512 KiB of source buffers. It is off by default, works with both
`--grant` and `--url`, and changes no wire fields. It does not pipeline receiver
writes or eliminate source hash preparation. See [measurements](docs/performance.md)
and [the I/O specification](docs/design.md#73-where-this-runs).

Socket buffers. Each end asks for 8 MiB of `SO_RCVBUF` and `SO_SNDBUF`. Linux caps that at `net.core.rmem_max` / `net.core.wmem_max` (often 208 KiB), and the helper runs as the host user, so it cannot force more. On a Linux host, as root:

```
printf 'net.core.rmem_max = 16777216\nnet.core.wmem_max = 16777216\n' > /etc/sysctl.d/90-sahxfer.conf
sysctl --system
```

sahxfer never sets a sysctl. `docs/design.md` §7.4 has the reasoning. On Linux the data path batches with `recvmmsg` and `sendmmsg`.

The portable path uses bounded 256 KiB source read-ahead, reusable authenticated-decryption scratch space, and direct streaming hashing of successfully written in-order DATA. Out-of-order ranges remain in the temp file. Repairs reread the source; final hash verification, fsync, and rename remain mandatory. See [performance measurements and remaining work](docs/performance.md) for reproducible single-file benchmarks and their limits.

`--url` accepts `https://`, or `http://` only to a loopback IP literal such as `http://127.0.0.1:3103`. `localhost` is refused.

## What this is

One regular file, one direction, one grant. The control client asks the hub to authorize the host, the root, the path, the size, and the hash (`GET /api/v1/hosts/resolve`, `POST /api/v1/xfer/grant`). That server is not in this repo. After the grant, file bytes do not travel on the WebSocket the agent already uses for shells and for `sahsync`.

The CLI data plane is UDP: a 64-byte header, ChaCha20-Poly1305, NACK repair, and pace-bbr. pace-bbr is the tested subset in this tree. It is not a byte-identical BBRv3. The portable I/O path is `pread` / `pwrite`. Linux opens paths with `openat2` (`RESOLVE_BENEATH`, no symlinks, no magic links) and does not fall back. Darwin walks each component with `O_NOFOLLOW`. That walk is not `openat2`.

`internal/quic` is a library. It requires TLS 1.3, ALPN `sahxfer/1`, and no 0-RTT. An optional 32-byte SPKI pin is checked after the chain and the name. The datagram runner and the stream runner each move one grant. The bridge copies sealed frames and does not hold the key. The CLI does not import that package, has no certificate flags, and still returns `agent_unsupported` for a QUIC grant.

## What this is not

| Tool | Job |
| --- | --- |
| `sahsync` | Many paths, sequential ops, WebSocket, the audited sync tool. Contract: `~/development/systemapi.io/docs/sah-file-protocol.md`. |
| `sahlink` | TCP byte relay over that same agent channel. |
| `sahconnect` | Login and the shell. sahxfer does not grow a second login. |
| `sahxfer` | One file. The CLI data plane is UDP. |

This repo is not in the suite Wired join. v1 is not directories, rsync, deltas, multi-file, or resume. A failed transfer deletes the temp and starts over. There is no `io_uring`, `sendfile`, `splice`, or `O_DIRECT`. `recv` does not drop uid. The agent must start it as the host user.

## Spec

`PROTOCOL.md` is the wire protocol. `docs/design.md` is the working spec, including the control plane, the path rules, and the decisions. Change the spec before code that follows a changed rule.
