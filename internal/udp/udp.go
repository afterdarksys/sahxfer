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
	"net"
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
type Config struct {
	Peer      *engine.Peer
	Conn      *net.UDPConn
	Connected bool
	Epoch     time.Duration
	Filter    func([]byte) bool
	Progress  func(delivered uint64)
}

// Run reads and writes until the peer finishes, fails, or ctx is done.
// A done context cancels the peer, sends its one ABORT best-effort, and
// returns ctx.Err() before any other mapping.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Peer == nil || cfg.Conn == nil {
		return code.New("internal")
	}
	defer cfg.Peer.Close()
	buf := make([]byte, frame.MaxDatagram)
	var remote *net.UDPAddr
	var queued [][]byte
	// The sender becomes OK when DONE checks out, then rate-limits the
	// CLOSE_ACK FIN until an RTT has passed. Stay up until that FIN is written.
	var finSent, closeSent bool
	var authentic bool
	var lastProg time.Time
	var progSent uint64
	cancel := func() error {
		cfg.Peer.Cancel(clock(cfg.Epoch))
		out := cfg.Peer.Take()
		if cfg.Connected || remote != nil {
			_ = flush(context.Background(), cfg, remote, out)
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
		if err := cfg.Conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
			if ctx.Err() != nil {
				return cancel()
			}
			return code.New("io")
		}
		n, addr, err := cfg.Conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				n = 0
			} else if refused(err) {
				// An ICMP port unreachable is not authenticated. The peer's
				// ABORT, if any, is still queued behind it.
				n = 0
			} else if ctx.Err() != nil {
				return cancel()
			} else {
				return code.New("io")
			}
		}
		if n > 0 && !cfg.Connected {
			if addr == nil || (remote != nil && addr.String() != remote.String()) {
				n = 0
			}
		}
		if n > 0 && (cfg.Filter == nil || !cfg.Filter(buf[:n])) {
			var ok bool
			if cfg.Connected || remote != nil {
				ok = cfg.Peer.Recv(clock(cfg.Epoch), buf[:n])
			} else {
				ok = cfg.Peer.RecvUnpinned(clock(cfg.Epoch), buf[:n])
			}
			if ok && !cfg.Connected && remote == nil {
				// Pin only after the datagram opened under the grant key.
				remote = copyAddr(addr)
				if err := flush(ctx, cfg, remote, queued); err != nil {
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
					authentic = true
					progSent = d
					lastProg = time.Now()
					cfg.Progress(d)
				}
			}
		}
		now = clock(cfg.Epoch)
		cfg.Peer.Pump(now)
		out := cfg.Peer.Take()
		note(out)
		if !cfg.Connected && remote == nil {
			queued = append(queued, out...)
		} else if err := flush(ctx, cfg, remote, out); err != nil {
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

func flush(ctx context.Context, cfg Config, remote *net.UDPAddr, pkts [][]byte) error {
	for _, p := range pkts {
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		if cfg.Connected {
			_, err = cfg.Conn.Write(p)
		} else {
			if remote == nil {
				return code.New("internal")
			}
			_, err = cfg.Conn.WriteToUDP(p, remote)
		}
		if err != nil && !refused(err) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return code.New("io")
		}
	}
	return nil
}

// refused is ECONNREFUSED from an ICMP port unreachable on a connected
// socket. Anyone on the path can forge one, so it does not end a transfer;
// the idle timer does.
func refused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
