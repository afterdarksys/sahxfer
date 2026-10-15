// Package udp runs one engine peer on a UDP socket.
//
// Threats: a second source after the peer is pinned, a cancel reported as
// an I/O failure, and a clock that is not the peer's clock. The runner does
// not log datagrams, keys, or route tokens. Epoch 0 is unix time in
// nanoseconds. A non-zero Epoch is subtracted from that clock so both
// processes can share one origin.
package udp

import (
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/frame"
)

// Config is one socket and one peer.
// Connected sockets use Write. A listener pins the first source, then
// WriteToUDP, and drops every later source.
// Filter returns true to drop a datagram before the engine sees it.
// The filter must not keep the slice.
type Config struct {
	Peer      *engine.Peer
	Conn      *net.UDPConn
	Connected bool
	Epoch     time.Duration
	Filter    func([]byte) bool
}

// Run reads and writes until the peer finishes, fails, or ctx is done.
// A done context returns ctx.Err() before any other mapping.
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
		if err := ctx.Err(); err != nil {
			return err
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
				return ctx.Err()
			}
			return code.New("io")
		}
		n, addr, err := cfg.Conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				n = 0
			} else if ctx.Err() != nil {
				return ctx.Err()
			} else {
				return code.New("io")
			}
		}
		if n > 0 && !cfg.Connected {
			if remote == nil {
				if addr == nil {
					n = 0
				} else {
					remote = copyAddr(addr)
					if err := flush(ctx, cfg, remote, queued); err != nil {
						return err
					}
					queued = nil
				}
			} else if addr == nil || addr.String() != remote.String() {
				n = 0
			}
		}
		if n > 0 && (cfg.Filter == nil || !cfg.Filter(buf[:n])) {
			cfg.Peer.Recv(clock(cfg.Epoch), buf[:n])
		}
		now = clock(cfg.Epoch)
		cfg.Peer.Pump(now)
		out := cfg.Peer.Take()
		note(out)
		if !cfg.Connected && remote == nil {
			queued = append(queued, out...)
		} else if err := flush(ctx, cfg, remote, out); err != nil {
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
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return code.New("io")
		}
	}
	return nil
}
