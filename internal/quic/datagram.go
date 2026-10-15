// Threats: sealed frames only, no second AEAD, a runner that returns
// before CLOSE_ACK is written, and a datagram the path cannot carry.
// Too large is protocol. Pacing stays off. The runner does not log
// frames or keys.
package quic

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"

	qgo "github.com/quic-go/quic-go"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/frame"
)

// Datagram is one engine peer on one QUIC connection.
// Epoch 0 is unix time in nanoseconds. A non-zero Epoch is subtracted
// from that clock so both processes can share one origin.
type Datagram struct {
	Peer  *engine.Peer
	Conn  *qgo.Conn
	Epoch time.Duration
}

// RunDatagram reads and writes until the peer finishes, fails, or ctx is done.
// The sender stays up until a CLOSE_ACK FIN has been handed to the connection.
// The connection is closed only when the parent context is done.
func RunDatagram(ctx context.Context, d Datagram) error {
	if d.Peer == nil || d.Conn == nil {
		return code.New("internal")
	}
	defer d.Peer.Close()
	if err := ctx.Err(); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			if err := d.Conn.CloseWithError(0, ""); err != nil && !errors.Is(err, net.ErrClosed) {
				select {
				case errCh <- err:
				default:
				}
			}
		case <-runCtx.Done():
		}
	}()

	sendCh := make(chan []byte)
	ackCh := make(chan struct{})
	go func() {
		for {
			var pkt []byte
			select {
			case <-runCtx.Done():
				return
			case pkt = <-sendCh:
			}
			if err := d.Conn.SendDatagram(pkt); err != nil {
				select {
				case errCh <- err:
				default:
				}
				return
			}
			select {
			case <-runCtx.Done():
				return
			case ackCh <- struct{}{}:
			}
		}
	}()

	recvCh := make(chan []byte, 32)
	recvErrCh := make(chan error, 1)
	go func() {
		for {
			b, err := d.Conn.ReceiveDatagram(runCtx)
			if err != nil {
				select {
				case recvErrCh <- err:
				case <-runCtx.Done():
				}
				return
			}
			select {
			case recvCh <- b:
			case <-runCtx.Done():
				return
			}
		}
	}()

	var pending [][]byte
	var inflight int
	var finSent, closeSent bool
	var recvFailed error
	timer := time.NewTimer(50 * time.Millisecond)
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	defer timer.Stop()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := clock(d.Epoch)
		d.Peer.Pump(now)
		out := d.Peer.Take()
		noteFIN(out, &finSent, &closeSent)
		for _, p := range out {
			pending = append(pending, append([]byte(nil), p...))
		}
		drained := len(pending) == 0 && inflight == 0
		if err := d.Peer.Err(); err != nil && drained {
			return err
		}
		if finished(d.Peer, finSent, closeSent) && drained {
			return nil
		}
		if recvFailed != nil && drained && !(finSent && !closeSent && d.Peer.OK()) {
			return mapDial(recvFailed)
		}

		sending := inflight == 0 && len(pending) > 0
		var timerC <-chan time.Time
		var outCh chan<- []byte
		var pkt []byte
		if sending {
			outCh = sendCh
			pkt = pending[0]
		} else {
			wait := 50 * time.Millisecond
			wake := d.Peer.WakeAt(now)
			if wake > now {
				if delta := wake - now; delta < wait {
					wait = delta
				}
			}
			if wait <= 0 {
				wait = 50 * time.Millisecond
			}
			timer.Reset(wait)
			timerC = timer.C
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if inflight > 0 {
				inflight--
			}
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if perr := d.Peer.Err(); perr != nil {
				return perr
			}
			if finished(d.Peer, finSent, closeSent) && len(pending) == 0 && inflight == 0 {
				return nil
			}
			return mapDial(err)
		case <-ackCh:
			inflight--
		case b := <-recvCh:
			if err := ctx.Err(); err != nil {
				return err
			}
			d.Peer.Recv(clock(d.Epoch), b)
		case err := <-recvErrCh:
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			recvFailed = err
		case <-timerC:
		case outCh <- pkt:
			pending = pending[1:]
			inflight++
		}
		if timerC != nil && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func finished(p *engine.Peer, finSent, closeSent bool) bool {
	return p.OK() && (!finSent || closeSent)
}

func noteFIN(pkts [][]byte, finSent, closeSent *bool) {
	for _, p := range pkts {
		if len(p) < frame.HeaderSize || p[5] != frame.TypeFIN {
			continue
		}
		*finSent = true
		flags := binary.LittleEndian.Uint16(p[6:8])
		if flags&frame.FlagCloseAck != 0 {
			*closeSent = true
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
