package engine

import (
	"bytes"
	"testing"

	"github.com/afterdarksys/sahxfer/internal/frame"
)

func TestPacketCacheOwnershipAndWipe(t *testing.T) {
	pr := newPair(t, []byte("abcd"), 4, nil)
	p := pr.s
	defer p.Close()
	p.EnablePacketReuse()
	p.send(0, frame.Header{Type: frame.TypeDATA}, []byte("first"))
	first := p.Take()
	owned := first[0]
	snapshot := append([]byte(nil), owned...)
	p.send(1, frame.Header{Type: frame.TypeDATA}, []byte("second"))
	second := p.Take()
	if !bytes.Equal(owned, snapshot) || &owned[0] == &second[0][0] {
		t.Fatal("outstanding batch reused")
	}
	p.ReleasePackets(first)
	if !bytes.Equal(owned[:cap(owned)], make([]byte, cap(owned))) {
		t.Fatal("released header/material retained")
	}
	p.send(2, frame.Header{Type: frame.TypeDATA}, []byte("third"))
	third := p.Take()
	if &third[0][0] != &owned[0] {
		t.Fatal("released buffer not reused")
	}
	p.ReleasePackets(second)
	p.ReleasePackets(third)
	p.Close()
	if p.packetCache != nil || !bytes.Equal(owned[:cap(owned)], make([]byte, cap(owned))) {
		t.Fatal("close retained cache")
	}
}

func TestPacketCacheBoundAndLegacyOwnership(t *testing.T) {
	pr := newPair(t, nil, 4, nil)
	defer pr.s.Close()
	p := pr.s
	p.send(0, frame.Header{Type: frame.TypePING}, nil)
	legacy := p.Take()
	snapshot := append([]byte(nil), legacy[0]...)
	p.ReleasePackets(legacy)
	if !bytes.Equal(legacy[0], snapshot) {
		t.Fatal("legacy output ownership changed")
	}
	p.EnablePacketReuse()
	for i := 0; i < 100; i++ {
		p.send(0, frame.Header{Type: frame.TypePING}, nil)
	}
	batch := p.Take()
	last := batch[len(batch)-1]
	p.ReleasePackets(batch)
	if len(p.packetCache) != packetCacheLimit {
		t.Fatalf("cache length %d", len(p.packetCache))
	}
	if !bytes.Equal(last[:cap(last)], make([]byte, cap(last))) {
		t.Fatal("overflow not wiped")
	}
}

func TestPacketCacheSizeClasses(t *testing.T) {
	pr := newPair(t, nil, 4, nil)
	p := pr.s
	defer p.Close()
	p.EnablePacketReuse()
	for _, size := range []int{1, frame.DCPlaintext, frame.InternetPlaintext} {
		pt := bytes.Repeat([]byte{7}, size)
		if !p.send(0, frame.Header{Type: frame.TypeDATA}, pt) {
			t.Fatal("send")
		}
		batch := p.Take()
		if cap(batch[0]) > frame.MaxDatagram {
			t.Fatal("unbounded buffer")
		}
		if size == 1 && cap(batch[0]) != frame.InternetDatagram {
			t.Fatal("oversized initial buffer")
		}
		_, opened, err := p.sess.Open(batch[0], p.cfg.LocalDir)
		if err != nil || !bytes.Equal(opened, pt) {
			t.Fatalf("size %d: %v", size, err)
		}
		p.ReleasePackets(batch)
	}
}
