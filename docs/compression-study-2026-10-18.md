sahxfer and data compression: measurements and recommendation
Date: 2026-10-18. Read-only investigation. The sahxfer repo was not modified.
Scratch work: /Users/ryan/tmp/claude-501/-Users-ryan-development/53f37f7e-823d-4665-9c54-95e304f3114a/scratchpad/compress/
  bench/      Go module (main.go, gen.go, pack.go), built offline with GOPROXY=off
  bench.txt   raw numbers, codec by block size by corpus
  pack.txt    raw numbers for the "pack several chunks into one datagram" variant
  mixed.txt   raw numbers for the incompressible-detection study


SHORT ANSWER

- Yes, a UDP data plane can be compressed reliably, as long as every unit you compress can be decoded without any other unit, and the repair unit (a datagram) and the compression unit (a block) are kept apart by a small amount of bookkeeping.
- It buys a lot for text, logs, JSON and source trees: 3.5 to 6 times faster on every link we care about, because the wire carries a quarter to a fifth of the bytes.
- It buys about 1.4 to 1.7 times for executables.
- It buys nothing for media, archives and anything already compressed or encrypted, and with a per-block "store raw if it did not shrink" rule it also costs almost nothing there: under 1.5 percent of the sender's CPU budget.
- Per-datagram compression (each 1152-byte payload alone) is the weak option: half the gain at text, and the datagram count does not drop, so it does not relieve the per-packet CPU cost that caps sahxfer at about 40 MB/s.
- Recommendation: optional per-block zstd (64 KiB blocks, fastest level), negotiated in the grant, off by default, with per-block raw fallback. Not for v1. For v1, do nothing in the protocol and document "compress first, then send" as the workaround, which gets the same or better ratio with zero protocol change.


PART 1. WHERE COMPRESSION COULD SIT

(a) Per-datagram. Each 1152-byte payload is compressed alone.
- Why it compresses poorly: a compressor finds repeats only inside its window, and here the window is the 1152 bytes of the one payload. A log line repeated 2 KB later is invisible. Measured with zstd fastest: logs 0.53 of original at 1152 bytes against 0.25 at 64 KiB; JSON 0.46 against 0.18; the source tar 0.30 against 0.18; the binary 0.71 against 0.62.
- It also does not reduce the number of datagrams. A compressed payload is a shorter datagram, but one per 1152 file bytes still. Sealing, syscalls and pacing are mostly per-packet costs, so on a CPU-bound path (1 Gbit LAN) the gain is far smaller than the byte ratio suggests.
- Packing variant, also measured: take a fixed grid of K file bytes, compress, and send it as one datagram if it fits in 1148 bytes, otherwise raw. Every datagram still decodes alone. Best case is exactly 2 datagrams into 1 (K = 2304) for logs and JSON; at K = 3456 the logs no longer fit at all; the binary saves 15 percent at best; throughput is 47 to 120 MB/s. This variant is dominated by per-block compression and is not worth pursuing.
- Protocol cost of (a) is small (a flag and an original length), which is its only virtue.

(b) Per-block. Fixed blocks of original bytes, for example 64 KiB or 256 KiB, each compressed alone, then the compressed stream is cut into ordinary 1152-byte DATA payloads.
- The wire offset of a byte is no longer its file offset. The receiver needs a block map (or in-band block headers) to know where each block starts in the wire stream and where its output goes in the file.
- The receiver can only decode a block once all of its datagrams are in. Today the temp file is the reassembly buffer (design §7.2) and holes are file ranges. With blocks, out-of-order bytes have to land somewhere in wire coordinates: a spool file, or memory bounded by the in-flight window. This is the largest change.
- Retransmission: the sender must resend exactly the same compressed bytes at a wire offset (the one-plaintext-per-offset rule, design §5). Either it keeps compressed blocks until the receiver's contiguous offset passes them, or it recompresses deterministically with the same encoder and level in the same process.
- Hash: unchanged if defined on the original file. The receiver hashes decoded output in order, which is what it does today with the contiguous prefix.
- byte_cap: today it counts unique file bytes. With blocks it has to count wire bytes, because the relay enforces the cap and only sees wire bytes. The bound is size plus block-header overhead (raw fallback guarantees the wire never exceeds that).
- Resume (out of v1, design §12): blocks make it easier, not harder. A restart can begin at a block boundary with a prefix hash of whole blocks. But wire offsets of a resumed grant restart at 0, so resume must be specified in block numbers, not wire offsets.
- FIN offset: the total wire length is not known until the sender has compressed the last block, so FIN carries the wire length, and the "span past size" check uses a maximum wire length until then.

(c) Whole-stream. One compressor over the whole file.
- Out. Decoding byte N needs every byte before N, so one lost datagram stalls everything after it until repaired, and the receiver cannot write anything out of order. That turns NACK repair into a head-of-line-blocked stream, which is TCP with extra steps. It also defeats first-write-wins idempotence, because a corrupt or missing early byte corrupts everything after it. If an operator wants whole-stream ratio, they can compress the file before sahxfer sees it.

Ordering and side channels
- Compression must happen before encryption. ChaCha20-Poly1305 output is indistinguishable from random and does not compress (the random corpus: ratio 1.0000 with every codec).
- Compressed size is a side channel (CRIME, BREACH). Those attacks need an attacker who can inject chosen plaintext into the same compression window as a secret, many times, and watch the length. sahxfer sends one file the sender already holds, with no attacker-controlled input mixed in, so that attack does not apply. What does leak: the relay and any on-path observer see the total wire length, so they learn roughly how compressible the file is (text-like or media-like). The grant already discloses size and sha256 to SAH. Per-datagram compression would leak more, because each datagram length shows the compressibility of each 1152-byte region. Per-block with full-size datagrams leaks only the total.


PART 2. MEASUREMENTS

Method
- Machine: Intel Core i9-9880H, 2.3 GHz, macOS, Go 1.27.1. runtime.GOMAXPROCS(1), so every figure is one core. Laptop with turbo; numbers are one run each, timed over at least 1.5 seconds and at least 64 MB of input per measurement. Expect about plus or minus 10 percent run to run.
- Codecs: Go stdlib compress/flate level 1 and 6; github.com/klauspost/compress v1.20.1 (present in the local module cache, built with GOPROXY=off) zstd SpeedFastest and SpeedDefault (encoder concurrency 1, CRC off), and s2 default. Encoders and decoders are reused across blocks, as a real implementation would.
- Every block is compressed independently. "Ratio" below is compressed size over original size with raw fallback: a block that does not shrink below 97 percent is counted at its original size. Every 97th block was round-tripped and compared.
- Throughput is in MB/s of original data (MB = 10^6 bytes). Decompression is measured over every block.

Corpora
- logs: 64 MiB of generated syslog lines, 40 hosts, 10 daemons, microsecond timestamps, random IPs, ports, PIDs and IDs.
- json: 64 MiB of generated API output, one host object per line with UUIDs, timestamps, nested CPU, memory and network fields.
- src.tar: uncompressed tar of /Users/ryan/development/sahxfer and sahsync, 9.2 MB (that is all there is; including .git). Not padded to 64 MB, because repetition at that distance would not change block-level results.
- src.tar.gz: the same tar, gzip -6, 1.5 MB.
- binary: copy of ~/go/bin/sahxfer, 11.1 MB.
- random: 64 MiB pseudo-random bytes.

Ratio with zstd fastest, by block size (1152 B, 16 KiB, 64 KiB, 256 KiB)
- logs: 0.530, 0.276, 0.248, 0.245
- json: 0.457, 0.203, 0.182, 0.176
- src.tar: 0.295, 0.193, 0.176, 0.167
- binary: 0.708, 0.627, 0.616, 0.602
- src.tar.gz: 0.998, 0.999, 1.000, 1.000
- random: 1.000 at every size

Most of the gain is reached by 16 KiB; 64 KiB gets within a few percent of 256 KiB.

Per corpus at 64 KiB blocks, each codec as ratio, compress MB/s, decompress MB/s

logs
- flate-1: 0.269, 169, 186
- flate-6: 0.238, 88, 212
- zstd-fastest: 0.248, 191, 804
- zstd-default: 0.243, 148, 845
- s2: 0.392, 544, 1301

json
- flate-1: 0.214, 234, 269
- flate-6: 0.189, 114, 296
- zstd-fastest: 0.182, 276, 1134
- zstd-default: 0.183, 213, 1135
- s2: 0.319, 926, 2264

src.tar
- flate-1: 0.187, 225, 291
- flate-6: 0.173, 151, 379
- zstd-fastest: 0.176, 451, 1681
- zstd-default: 0.171, 382, 1700
- s2: 0.216, 1392, 2851

binary
- flate-1: 0.627, 123, 122
- flate-6: 0.583, 54, 126
- zstd-fastest: 0.616, 148, 686
- zstd-default: 0.588, 95, 572
- s2: 0.701, 464, 1222

src.tar.gz (already compressed)
- all codecs: 1.000 after fallback. Compress speed: flate-1 1043, flate-6 633, zstd-fastest 7703, zstd-default 3307, s2 7279.

random
- all codecs: 1.000 after fallback. Compress speed: flate-1 3216, flate-6 2051, zstd-fastest 3818, zstd-default 2491, s2 4416.

Per-datagram (1152-byte blocks), compress MB/s with zstd fastest
- logs 84, json 99, src.tar 110, binary 66, random 854.
- s2 at 1152: 418 to 940 MB/s but ratio only 0.62 to 0.77 on text and binary.
- flate at 1152: 24 to 65 MB/s, slower than sahxfer's whole pipeline.

256 KiB blocks, zstd default (the best ratio tried): logs 0.238 at 133 MB/s, json 0.179 at 197, src.tar 0.162 at 379, binary 0.581 at 90.

Observations
- zstd fastest dominates flate-1 on every corpus: same or better ratio, faster compression, 3 to 6 times faster decompression.
- zstd default buys 1 to 5 percent smaller output over fastest at 20 to 40 percent lower speed. Not worth it for a transfer tool.
- s2 is 2 to 3 times faster than zstd fastest but leaves 1.3 to 1.8 times as many bytes on text.
- On incompressible input, zstd fastest and s2 bail out fast: 3.8 to 7.7 GB/s at 64 KiB. That is the property that makes a separate sampler mostly unnecessary (part 4).


PART 3. AGAINST SAHXFER'S BUDGET

Model
- The current pipeline (read, seal, send on the sender; receive, open, write, hash on the receiver) moves about 40 MB/s per core on loopback, sender near one core (14 to 15 s user per GB, plus system time). I treat 40 MB/s per core of wire bytes as the CPU ceiling on each side.
- Links: WAN 20 Mbit/s = 2.5 MB/s; LAN 100 Mbit/s = 12.5 MB/s; WAN 200 Mbit/s = 25 MB/s; LAN 1 Gbit/s = 125 MB/s.
- Baseline goodput = min(link, 40). Note that a 1 Gbit LAN is already CPU-bound today at 40 MB/s.
- With compression ratio r, compress speed C, decompress speed D:
  Same core (compressor in the send loop): min(1 / (1/C + r/40), 1 / (1/D + r/40), link / r).
  Separate core (compressor in its own goroutine, pipelined): min(C, D, 40/r, link/r).
- Speed-up = goodput with compression / baseline. Above 1 is faster.
- For per-datagram (1152) rows the model is optimistic, because it scales the 40 MB/s cost with wire bytes, while the datagram count, and so the per-packet cost, does not drop.
- The pacing step (about 75 KB per 1 ms at 75 MB/s) does not enter: compression changes the bytes per packet budget, not the pacer's granularity, and pacing at a lower wire rate only makes the 1 ms catch-up burst smaller.

Speed-ups. Each line: WAN 20 Mbit, LAN 100 Mbit, WAN 200 Mbit, LAN 1 Gbit. Where same-core and separate-core differ, the same-core figure is given first and the separate-core figure in brackets.

logs
- per-datagram zstd fastest: 1.89, 1.89, 1.59 (1.89), 1.00 (1.89)
- s2, 64 KiB: 2.55, 2.55, 2.55, 2.15 (2.55)
- zstd fastest, 64 KiB: 4.03, 4.03, 3.50 (4.03), 2.19 (4.03)
- zstd default, 256 KiB: 4.20, 4.20, 2.97 (4.20), 1.86 (3.33)
- flate-1, 64 KiB: 3.71, 3.71, 3.16 (3.71), 1.97 (3.71)

json
- per-datagram zstd fastest: 2.19, 2.19, 1.86 (2.19), 1.16 (2.19)
- s2, 64 KiB: 3.13, 3.13, 3.13, 2.76 (3.13)
- zstd fastest, 64 KiB: 5.50, 5.50, 4.90 (5.50), 3.06 (5.50)
- zstd default, 256 KiB: 5.60, 5.60, 4.19 (5.60), 2.62 (4.92)
- flate-1, 64 KiB: 4.68, 4.68, 4.16 (4.68), 2.60 (4.68)

src.tar
- per-datagram zstd fastest: 3.39, 3.39, 2.43 (3.39), 1.52 (2.76)
- s2, 64 KiB: 4.64, 4.64, 4.64, 4.09 (4.64)
- zstd fastest, 64 KiB: 5.68, 5.68, 5.68, 3.78 (5.68)
- zstd default, 256 KiB: 6.16, 6.16, 5.97 (6.16), 3.73 (6.16)
- flate-1, 64 KiB: 5.34, 5.34, 4.39 (5.34), 2.74 (5.34)

binary
- per-datagram zstd fastest: 1.41, 1.41, 1.22 (1.41), 0.76 (1.41). A slow-down on 1 Gbit if on the same core.
- s2, 64 KiB: 1.43, 1.43, 1.43, 1.27 (1.43)
- zstd fastest, 64 KiB: 1.62, 1.62, 1.62, 1.13 (1.62)
- zstd default, 256 KiB: 1.72, 1.72, 1.56 (1.72), 0.97 (1.72). A slight slow-down on 1 Gbit same-core.
- flate-1, 64 KiB: 1.59, 1.59, 1.59, 1.05 (1.59)

src.tar.gz and random (incompressible)
- Every codec at 64 KiB or 256 KiB: 1.00 on the WAN links and the 100 Mbit LAN; 0.98 to 0.99 on 1 Gbit same-core; 1.00 on a separate core.
- Per-datagram zstd fastest: 0.96 on 1 Gbit same-core.

Reading the numbers
- On the WAN links and the 100 Mbit LAN the link is the bottleneck, so the speed-up is simply 1 / ratio, for every codec. Compression CPU never becomes the bottleneck there: zstd fastest at 64 KiB runs at 148 MB/s even on the binary, 12 to 60 times faster than those links.
- On 1 Gbit LAN the CPU is the bottleneck today. Compression on the same core still wins for text (2 to 4 times) because sealing and sending fewer bytes saves more CPU than compressing costs. On a separate core it reaches the full 1 / ratio.
- The worst measured case is a 4 percent slow-down (per-datagram, incompressible, 1 Gbit, same core). With 64 KiB blocks the worst case is 1 to 2 percent.
- zstd fastest at 64 KiB is the best balance: within 5 percent of the best ratio on every corpus, and never below 1.13 on the 1 Gbit same-core case for compressible data.


PART 4. INCOMPRESSIBLE DETECTION

Question: can a cheap sampler (compress the first N KiB, skip compression if the ratio is above 0.9) decide per file?

Test
- 5000 synthetic mixed files, each a concatenation of 2 to 40 segments. Each segment is a contiguous run of 64 KiB blocks (64 KiB to 16 MiB, log-uniform) drawn at random from seven pools: logs, json, src.tar, binary (compressible) and real media (two mp4, three mp3, one jpg from brooklyncats.show, 46 MB), src.tar.gz, random (incompressible). This imitates a tar of a project directory with text and media in arbitrary order.
- Truth: the file's ratio with zstd fastest at 64 KiB blocks and raw fallback. A file is "compressible" if that ratio is at most 0.9. 4779 files were compressible, 221 were not.
- False negative: sampler says skip, file is compressible. False positive: sampler says compress, file is not.
- Media pool check: the mp4, mp3 and jpg blocks compress to 0.999, i.e. not at all.

Results
- First 64 KiB: false negatives 44.1 percent of compressible files; 43 percent of all possible savings lost. False positives 24 percent.
- First 256 KiB: false negatives 38.1 percent; 37 percent of savings lost. False positives 27 percent.
- First 1 MiB: false negatives 33.9 percent; 33 percent of savings lost. False positives 21 percent.
- 8 probes of 64 KiB spread evenly through the file: false negatives 1.8 percent; 0.8 percent of savings lost. False positives 23 percent.
- 16 probes of 64 KiB spread evenly: false negatives 0.8 percent; 0.3 percent of savings lost. False positives 7.7 percent.
- Per-block adaptive backoff (after an incompressible block, skip the next 1, 2, 4 up to 64 blocks, reset on a compressible block): tries 52 percent of blocks, loses 10.9 percent of the savings.

What this means
- A prefix sampler is wrong a third to almost half the time on mixed files, because the file's head says nothing about its tail. Do not use it.
- A strided sampler (16 by 64 KiB, 1 MiB of reads) is accurate enough to decide whether to ask for compression at all, for example in the client before requesting a grant.
- Inside a transfer, no sampler is needed. Try every block and keep the raw block if it did not shrink. zstd fastest on incompressible 64 KiB blocks runs at 3.8 GB/s (random) and 2.7 GB/s (the media pool) on one core, that is 0.26 to 0.37 ms of CPU per MB, against the 25 ms per MB the pipeline already spends at 40 MB/s: about 1 to 1.5 percent. The backoff heuristic saves that 1 percent and gives up 11 percent of the savings, a bad trade.


PART 5. RECOMMENDATION

Choice: optional per-block zstd, negotiated in the grant, off by default, with per-block raw fallback as the incompressible skip. Scheduled as a v2 item, not added to v1.

Why not "do nothing" forever
- For text, logs, JSON and source trees the gain is 3.5 to 6 times on every link in the target range, and still 2 to 4 times on a CPU-bound 1 Gbit LAN. Those are common payloads for an ops tool.

Why not always-on
- No gain for media, archives, backups that are already compressed, or encrypted files, which are likely the largest files people move.
- It puts a decompressor on the agent for every grant, which is new attack surface (decompression bombs, decoder bugs) on the receiving host.
- It adds receiver spool I/O and changes byte_cap semantics for every transfer.
- Binary on a 1 Gbit LAN with the compressor on the send core is a measured 3 percent slow-down at zstd default.

Why defer it past v1
- v1 deliberately makes the temp file the reassembly buffer and every offset a file offset. Per-block compression breaks both. That is a protocol version, not a flag.
- The zero-change workaround gets the same benefit today: compress first (zstd -1 -T0), send the .zst, decompress on the far side. Whole-file zstd beats 64 KiB blocks on ratio. It costs a temp file on each end and an extra step, which is acceptable until the feature exists. Document it in the README.

What the protocol would need (a concrete v2 sketch)
1. Grant field. compression: "none" or "zstd". A server choice, like profile; the client may request it (for example after the 16-probe sampler) but cannot force it. "none" is the default and is exactly v1. Unknown value is mismatch. Bump the datagram version to 2 for zstd grants so a v1 peer drops the packets instead of writing compressed bytes into a file.
2. Fixed block size in the spec, not negotiated: 64 KiB of original file bytes. Block i is original bytes [i x 65536, min(size, (i+1) x 65536)). The block count is known from size.
3. Wire stream. The concatenation, in block order, of: an 8-byte block header (u8 mode: 0 raw, 1 zstd; 3 reserved bytes; u32 encoded length) followed by the encoded block. DATA offset is the wire offset. DATA payloads stay at 1152 bytes and may span block boundaries.
4. No separate block-map frame. Because decoding and hashing happen in order on the contiguous prefix anyway, the receiver learns each block's position by reading the in-band headers as the contiguous prefix grows. This keeps NACK, FEEDBACK, RETX and the stall probe unchanged, just in wire coordinates.
5. Size limits. Maximum wire length = size + 8 x block count (raw fallback guarantees it). DATA past that aborts with protocol. FIN offset is the actual wire length. NACK holes and the hole map are in wire coordinates; the map starts as [0, max wire length) and is trimmed at FIN.
6. Decoder rules, all fail closed with protocol: mode other than 0 or 1; raw block whose length is not the block's original length; zstd block that decodes to anything other than the block's original length (use a decoder limited to 64 KiB output, no dictionary, window at most 64 KiB, frame must declare its content size); an encoded zstd block not smaller than its original (a sender must use raw then); trailing wire bytes after the last block; total decoded length other than size.
7. Hash semantics: unchanged. sha256 is of the original file, folded over decoded bytes in order. DONE carries it as today.
8. byte_cap: counts unique wire bytes, sealed by the sender for the first time and accepted by the receiver, and the grant issues byte_cap of at least the maximum wire length. The relay's forwarding cap is unchanged in meaning (it already counts what it forwards).
9. Receiver storage: out-of-order wire bytes go to a spool file (.sahxfer-<grant_id>.spool, same open rules as the temp), the "file is the reassembly buffer" rule moves to the spool. Decoded blocks are pwritten to the temp file in order. Commit order unchanged, and the spool is deleted on commit and on abort. Extra disk I/O is about r times size.
10. Sender: compress blocks ahead in a goroutine (the separate-core figures in part 3), keep encoded blocks until the receiver's contiguous wire offset passes them so a RETX resends identical bytes. Memory is bounded by the in-flight window plus one block.
11. quic-stream is untouched in this sketch; it could take the same block format later.
12. New dependency: github.com/klauspost/compress. It is not in sahxfer's go.mod today, so it needs the usual supply-chain review. The stdlib has no zstd; flate-1 is the stdlib fallback and costs about 10 to 20 percent ratio and 4 to 6 times the decode CPU.

Implementation estimate
- Grant field, validation, version 2 gating: about 80 lines plus 120 lines of tests.
- Block codec (header, raw fallback, bounded decoder): about 150 lines plus 250 lines of tests, including the fail-closed cases in item 6 and a decompression bomb.
- Sender block pipeline and encoded-block cache for RETX: about 250 lines.
- Receiver spool, in-order decoder, wire-coordinate hole map, byte_cap change: about 350 lines.
- Engine tests under loss and reorder with compression on, and the spool cleanup paths: about 400 lines.
- Spec text in PROTOCOL.md and design.md: about 1.5 pages.
- Total: roughly 800 to 900 lines of production code and 750 to 800 lines of tests, against about 15,000 lines in the repo today. A week of careful work, most of it on the receiver.


LIMITATIONS

- One machine (a 2019 laptop i9 with turbo), one run per number, no confidence intervals. Server CPUs, especially with AVX-512 and without thermal limits, will be faster for both the codecs and the existing pipeline; the ratios between them should hold roughly.
- The 40 MB/s ceiling and its split between per-byte and per-packet cost come from the owner's loopback measurement, not from a profile I ran. If most of that cost is per-packet, per-block compression gains more on 1 Gbit than modeled (fewer datagrams) and per-datagram compression gains less.
- The receiver is assumed to have the same 40 MB/s ceiling as the sender. Receiver spool I/O is not modeled.
- Corpora are synthetic for logs and JSON. Real logs often compress better (more repetition), real JSON from one API often better too. The source tar is only 9.2 MB.
- The mixed-file study draws segments at random; real directory trees cluster (all media together, or text first), so real prefix-sampler error may be lower or higher. The false-positive rates rest on only 221 incompressible files.
- The packing variant used a 4-byte sub-header and a fixed grid; a smarter variable grid could do slightly better but keeps the same per-datagram window ceiling.
- No measurement was made on the real sahxfer engine with compression wired in; part 3 is a model built from codec throughput and the stated budget.
