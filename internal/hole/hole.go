// Package hole is the receiver's interval map of missing file bytes.
//
// Threats: a range that wraps or runs past the grant size is rejected and
// the map is left unchanged. A replay does not increase delivered bytes.
// The map does not hold file bytes and does not decide what gets written.
// An interior hole (some accepted end past the hole) is mature at once.
// The trailing edge is not a hole until FIN, and then only once it is older
// than max(3*srtt, 1ms) and a later seq has been accepted.
package hole

import (
	"errors"
	"sort"
	"time"

	"github.com/afterdarksys/sahxfer/internal/frame"
)

// ErrRange is an empty, inverted, wrapping, or past-size range.
var ErrRange = errors.New("sahxfer: range")

// ErrSize is a grant size the map will not track.
var ErrSize = errors.New("sahxfer: size")

type span struct {
	start    uint64
	end      uint64
	born     time.Duration
	birthSeq uint64
	later    bool
}

// Map is the missing ranges of one file. Size 0 is an empty map.
type Map struct {
	size      uint64
	missing   []span
	maxEnd    uint64
	delivered uint64
	fin       bool
}

// New starts the map as the single hole [0, size). size must be < 2^63.
func New(size uint64) (*Map, error) {
	if size >= 1<<63 {
		return nil, ErrSize
	}
	m := &Map{size: size}
	if size > 0 {
		m.missing = []span{{start: 0, end: size}}
	}
	return m, nil
}

// Accept marks [start, end) present. seq is the packet that carried it.
// newly is how many bytes were still missing. A pure replay returns 0, nil.
func (m *Map) Accept(start, end uint64, seq uint64, now time.Duration) (uint64, error) {
	if start >= end || end > m.size {
		return 0, ErrRange
	}
	var wrote uint64
	next := make([]span, 0, len(m.missing)+1)
	for _, h := range m.missing {
		if seq > h.birthSeq {
			h.later = true
		}
		if end <= h.start || start >= h.end {
			next = append(next, h)
			continue
		}
		if h.start < start {
			left := h
			left.end = start
			next = append(next, left)
		}
		lo := h.start
		if start > lo {
			lo = start
		}
		hi := h.end
		if end < hi {
			hi = end
		}
		wrote += hi - lo
		if h.end > end {
			next = append(next, span{
				start:    end,
				end:      h.end,
				born:     now,
				birthSeq: seq,
			})
		}
	}
	m.missing = next
	if wrote > 0 && end > m.maxEnd {
		m.maxEnd = end
	}
	m.delivered += wrote
	return wrote, nil
}

// NoteFIN records that the sender claims every byte was transmitted.
// The trailing gap becomes eligible to mature. It is not mature yet.
// now is the receiver clock. The gap keeps the birth time from when it
// opened; FIN contributes the later sequence.
func (m *Map) NoteFIN(seq uint64, now time.Duration) {
	m.fin = true
	_ = now
	for i := range m.missing {
		if seq > m.missing[i].birthSeq {
			m.missing[i].later = true
		}
	}
}

// Mature returns mature holes, oldest first. srtt is the smoothed RTT.
// The caller sends at most frame.MaxNACKHoles of them.
func (m *Map) Mature(now, srtt time.Duration) []frame.Span {
	thresh := 3 * srtt
	if thresh < time.Millisecond {
		thresh = time.Millisecond
	}
	type item struct {
		s    frame.Span
		born time.Duration
	}
	var items []item
	for _, h := range m.missing {
		if m.maxEnd > h.end {
			items = append(items, item{frame.Span{Start: h.start, End: h.end}, h.born})
			continue
		}
		if !m.fin || !h.later || now-h.born < thresh {
			continue
		}
		items = append(items, item{frame.Span{Start: h.start, End: h.end}, h.born})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].born != items[j].born {
			return items[i].born < items[j].born
		}
		return items[i].s.Start < items[j].s.Start
	})
	out := make([]frame.Span, len(items))
	for i, it := range items {
		out[i] = it.s
	}
	return out
}

// Contiguous is the highest offset such that [0, Contiguous) is filled.
func (m *Map) Contiguous() uint64 {
	if len(m.missing) == 0 {
		return m.size
	}
	return m.missing[0].start
}

// Delivered is the count of unique bytes accepted.
func (m *Map) Delivered() uint64 { return m.delivered }

// Empty reports whether every byte is present.
func (m *Map) Empty() bool { return len(m.missing) == 0 }

// FinSeen reports whether NoteFIN has been called.
func (m *Map) FinSeen() bool { return m.fin }

// Size is the grant size.
func (m *Map) Size() uint64 { return m.size }

// Missing is a copy of the holes still open, in offset order.
func (m *Map) Missing() []frame.Span {
	out := make([]frame.Span, len(m.missing))
	for i, h := range m.missing {
		out[i] = frame.Span{Start: h.start, End: h.end}
	}
	return out
}
