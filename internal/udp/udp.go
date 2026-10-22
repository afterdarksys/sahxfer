// Package udp runs one engine peer on a UDP socket.
//
// Threats: a forged first datagram that pins the wrong source, a second
// source after the peer is pinned, a cancel reported as an I/O failure or
// left unannounced to the peer, and a clock that is not the peer's clock. The runner does
// not log datagrams, keys, or route tokens. Epoch 0 is unix time in
// nanoseconds. A non-zero Epoch is subtracted from that clock so both
// processes can share one origin.
package udp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/frame"
)

// Config is one socket and one peer.
// Connected sockets use Write. A listener pins the first source whose
// datagram the peer reports authentic, then uses WriteToUDP and drops every
// other source. Until then any source may be offered to the peer.
// Filter returns true to drop a datagram before the engine sees it.
// The filter must not keep the slice.
// Progress, when set, is called with the delivered byte count on the first
// authentic datagram and then at most once a second while it changes.
// RcvBuf is the granted receive buffer (TuneBuffers). With Diag set, a
// data receiver checks once a second whether the usable part of it is
// below its arrival rate times max(RTprop, 5 ms) and calls Diag with one
// "diag warn" line the first time it is (docs/design.md section 7.4).
// With Diag set, a UDP sender also reports its pacing counters at most
// once a second. These lines never contain grant material or file bytes.
type Config struct {
	Peer      *engine.Peer
	Conn      *net.UDPConn
	Connected bool
	Epoch     time.Duration
	Filter    func([]byte) bool
	Progress  func(delivered uint64)
	RcvBuf    int
	Diag      func(line string)
}

// WantBuffer is the SO_RCVBUF and SO_SNDBUF each end asks for.
const WantBuffer = 8 << 20

// rxPkt is one received datagram and its source (nil when connected).
type rxPkt struct {
	b    []byte
	addr *net.UDPAddr
}

// errDeadline is a socket that could not take a deadline.
var errDeadline = errors.New("udp: deadline")

// Run reads and writes until the peer finishes, fails, or ctx is done.
// A done context cancels the peer, sends its one ABORT best-effort, and
// returns ctx.Err() before any other mapping.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Peer == nil || cfg.Conn == nil {
		return code.New("internal")
	}
	defer cfg.Peer.Close()
	sio := newSockIO(cfg.Conn, cfg.Connected)
	var remote *net.UDPAddr
	var queued [][]byte
	// The sender becomes OK when DONE checks out, then rate-limits the
	// CLOSE_ACK FIN until an RTT has passed. Stay up until that FIN is written.
	var finSent, closeSent bool
	var authentic bool
	var lastProg time.Time
	var progSent uint64
	var warned bool
	var lastCheck time.Time
	var lastPace time.Time
	cancel := func() error {
		cfg.Peer.Cancel(clock(cfg.Epoch))
		out := cfg.Peer.Take()
		if cfg.Connected || remote != nil {
			_ = flush(context.Background(), sio, remote, out)
		}
		return ctx.Err()
	}
	note := func(pkts [][]byte) {
		for _, p := range pkts {
			if len(p) < frame.HeaderSize || p[5] != frame.TypeFIN {
				continue
			}
			finSent = true
			flags := binary.LittleEndian.Uint16(p[6:8])
			if flags&frame.FlagCloseAck != 0 {
				closeSent = true
			}
		}
	}
	for {
		if ctx.Err() != nil {
			return cancel()
		}
		now := clock(cfg.Epoch)
		wake := cfg.Peer.WakeAt(now)
		wait := 50 * time.Millisecond
		if wake <= now {
			wait = 0
		} else if d := wake - now; d < wait {
			wait = d
		}
		pkts, err := sio.read(wait)
		if err != nil {
			pkts = nil
			if errors.Is(err, errDeadline) {
				if ctx.Err() != nil {
					return cancel()
				}
				return code.New("io")
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() || errors.Is(err, os.ErrDeadlineExceeded) {
				// No datagram before the wait ran out.
			} else if refused(err) {
				// An ICMP port unreachable is not authenticated. The peer's
				// ABORT, if any, is still queued behind it.
			} else if ctx.Err() != nil {
				return cancel()
			} else {
				return code.New("io")
			}
		}
		for _, pk := range pkts {
			if len(pk.b) == 0 {
				continue
			}
			if !cfg.Connected {
				if pk.addr == nil || (remote != nil && pk.addr.String() != remote.String()) {
					continue
				}
			}
			if cfg.Filter != nil && cfg.Filter(pk.b) {
				continue
			}
			var ok bool
			if cfg.Connected || remote != nil {
				ok = cfg.Peer.Recv(clock(cfg.Epoch), pk.b)
			} else {
				ok = cfg.Peer.RecvUnpinned(clock(cfg.Epoch), pk.b)
			}
			if ok && !cfg.Connected && remote == nil {
				// Pin only after the datagram opened under the grant key.
				remote = copyAddr(pk.addr)
				if err := flush(ctx, sio, remote, queued); err != nil {
					if ctx.Err() != nil {
						return cancel()
					}
					return err
				}
				queued = nil
			}
			if ok && cfg.Progress != nil {
				d := cfg.Peer.Delivered()
				if !authentic || (d != progSent && time.Since(lastProg) >= time.Second) {
					progSent = d
					lastProg = time.Now()
					cfg.Progress(d)
				}
			}
			if ok {
				authentic = true
			}
		}
		if cfg.Diag != nil && !warned && authentic && cfg.RcvBuf > 0 && time.Since(lastCheck) >= time.Second {
			if !lastCheck.IsZero() {
				warned = checkRcvBuf(cfg, clock(cfg.Epoch))
			}
			lastCheck = time.Now()
		}
		now = clock(cfg.Epoch)
		cfg.Peer.Pump(now)
		if cfg.Diag != nil && authentic && time.Since(lastPace) >= time.Second {
			if line := cfg.Peer.PacingDiagnostic(); line != "" {
				cfg.Diag(line)
			}
			lastPace = time.Now()
		}
		out := cfg.Peer.Take()
		note(out)
		if !cfg.Connected && remote == nil {
			queued = append(queued, out...)
		} else if err := flush(ctx, sio, remote, out); err != nil {
			if ctx.Err() != nil {
				return cancel()
			}
			return err
		}
		if err := cfg.Peer.Err(); err != nil {
			return err
		}
		if cfg.Peer.OK() && (!finSent || closeSent) {
			return nil
		}
	}
}

// checkRcvBuf writes one diag warn line when the data receiver's usable
// receive buffer is short, and reports whether it did.
func checkRcvBuf(cfg Config, now time.Duration) bool {
	rate, rtt := cfg.Peer.RecvRate(now)
	line, short := rcvBufWarn(cfg.RcvBuf, rate, rtt)
	if short {
		cfg.Diag(line)
	}
	return short
}

// rcvBufWarn compares the usable part of a granted receive buffer with
// rate * max(rtt, 5 ms) (docs/design.md section 7.4).
func rcvBufWarn(rcvbuf int, rate float64, rtt time.Duration) (string, bool) {
	if rate <= 0 || rcvbuf <= 0 {
		return "", false
	}
	if rtt < 5*time.Millisecond {
		rtt = 5 * time.Millisecond
	}
	need := rate * rtt.Seconds()
	if float64(usableRcv(rcvbuf)) >= need {
		return "", false
	}
	return fmt.Sprintf("diag warn rcvbuf=%d usable=%d need=%.0f rate=%.0f rtt=%s", rcvbuf, usableRcv(rcvbuf), need, rate, rtt.Round(time.Microsecond)), true
}

func clock(epoch time.Duration) time.Duration {
	now := time.Duration(time.Now().UnixNano())
	if epoch == 0 {
		return now
	}
	return now - epoch
}

func copyAddr(a *net.UDPAddr) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
}

func flush(ctx context.Context, sio *sockIO, remote *net.UDPAddr, pkts [][]byte) error {
	if len(pkts) == 0 {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !sio.connected && remote == nil {
		return code.New("internal")
	}
	if err := sio.write(pkts, remote); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return code.New("io")
	}
	return nil
}

// refused is ECONNREFUSED from an ICMP port unreachable on a connected
// socket. Anyone on the path can forge one, so it does not end a transfer;
// the idle timer does.
func refused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
