package engine

import "github.com/afterdarksys/sahxfer/internal/frame"

const packetCacheLimit = 64

// EnablePacketReuse opts a synchronous transport into ReleasePackets. It must
// be called before sending. Without this opt-in, Take retains ordinary owned
// outputs and callers need not release anything. Peer remains single-owner.
func (p *Peer) EnablePacketReuse() { p.reusePackets = true }

// ReleasePackets ends the caller's ownership of an entire Take batch. Call
// exactly once, after every consumer (including a partial-send retry) finishes.
// No slice or datagram in the batch may be used afterward. Never release
// foreign or duplicated buffers. Overflow is wiped and left for GC.
func (p *Peer) ReleasePackets(pkts [][]byte) {
	if !p.reusePackets {
		return
	}
	for i, b := range pkts {
		clear(b[:cap(b)])
		if p.sess != nil && cap(b) <= frame.MaxDatagram && cap(b) >= frame.Overhead && len(p.packetCache) < packetCacheLimit {
			p.packetCache = append(p.packetCache, b[:0])
		}
		pkts[i] = nil
	}
	// A synchronous runner normally has one outstanding batch. Only retain
	// modest slice metadata; it must not alias a batch still in transport use.
	if p.sess != nil && len(p.out) == 0 && cap(pkts) <= packetCacheLimit {
		p.out = pkts[:0]
	}
}

func (p *Peer) packetBuffer(need int) []byte {
	if !p.reusePackets {
		return nil
	}
	n := len(p.packetCache)
	if n > 0 {
		b := p.packetCache[n-1]
		p.packetCache[n-1] = nil
		p.packetCache = p.packetCache[:n-1]
		if cap(b) >= need {
			return b
		}
		// Already wiped on release. Discard a smaller size class rather than
		// retaining a second unbounded collection of unsuitable buffers.
	}
	size := frame.InternetPlaintext + frame.Overhead
	if need > size {
		size = frame.MaxDatagram
	}
	return make([]byte, 0, size)
}
