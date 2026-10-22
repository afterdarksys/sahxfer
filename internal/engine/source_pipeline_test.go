package engine

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/frame"
)

type gatedSource struct {
	body    []byte
	started chan []byte
	release chan struct{}
}

func (r *gatedSource) ReadAt(b []byte, off int64) (int, error) {
	if off != 0 {
		r.started <- b
		<-r.release
	}
	return bytes.NewReader(r.body).ReadAt(b, off)
}

func TestSourcePipelineOverlapsAndJoins(t *testing.T) {
	r := &gatedSource{body: bytes.Repeat([]byte{7}, 600<<10), started: make(chan []byte, 1), release: make(chan struct{})}
	p := &Peer{cfg: Config{Size: uint64(len(r.body)), MSS: 1152, SourcePipeline: true}, src: r}
	buf := make([]byte, 1152)
	if err := p.readSource(buf, 0, false); err != nil {
		t.Fatal(err)
	}
	var pending []byte
	select {
	case pending = <-r.started:
	case <-time.After(time.Second):
		t.Fatal("read-ahead did not start")
	}
	// Current block remains usable while the next read is blocked.
	if err := p.readSource(buf, 1152, false); err != nil || !bytes.Equal(buf, r.body[:1152]) {
		t.Fatalf("active buffer: %v", err)
	}
	active := p.sourceBuf
	closed := make(chan struct{})
	go func() { p.Close(); close(closed) }()
	select {
	case <-closed:
		t.Fatal("Close returned before outstanding read")
	case <-time.After(10 * time.Millisecond):
	}
	close(r.release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close did not join worker")
	}
	for _, b := range [][]byte{active, pending} {
		if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
			t.Fatal("plaintext retained")
		}
	}
	p.Close()
}

type failingSource struct {
	body   []byte
	failAt int64
	short  bool
}

func (r failingSource) ReadAt(b []byte, off int64) (int, error) {
	if off >= r.failAt {
		if r.short {
			return 1, nil
		}
		return 0, io.ErrUnexpectedEOF
	}
	return bytes.NewReader(r.body).ReadAt(b, off)
}

func TestSourcePipelineReadFailure(t *testing.T) {
	for _, short := range []bool{false, true} {
		const block = sourceBlockSize / 1152 * 1152
		p := &Peer{cfg: Config{Size: 600 << 10, MSS: 1152, SourcePipeline: true}, src: failingSource{body: make([]byte, 600<<10), failAt: block, short: short}}
		buf := make([]byte, 1152)
		if err := p.readSource(buf, 0, false); err != nil {
			t.Fatal(err)
		}
		if err := p.readSource(buf, block, false); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("partial prefetch accepted: %v", err)
		}
		p.Close()
	}
}

func TestSourcePipelineSkipsAndRepairs(t *testing.T) {
	body := make([]byte, 2<<20)
	for i := range body {
		body[i] = byte(i*7 + i>>11)
	}
	p := &Peer{cfg: Config{Size: uint64(len(body)), MSS: 1152, SourcePipeline: true}, src: bytes.NewReader(body)}
	defer p.Close()
	buf := make([]byte, 1152)
	for _, off := range []uint64{0, 1152, 1152 * 1000, 1152 * 1001, 0} {
		if err := p.readSource(buf, off, false); err != nil || !bytes.Equal(buf, body[off:off+1152]) {
			t.Fatalf("offset %d: %v", off, err)
		}
	}
	// A separate source proves repairs bypass both lookahead buffers.
	p.src = bytes.NewReader(bytes.Repeat([]byte{99}, len(body)))
	if err := p.readSource(buf, 0, true); err != nil || buf[0] != 99 {
		t.Fatalf("repair: %v", err)
	}
}

func TestSourcePipelineTransfer(t *testing.T) {
	for _, size := range []int{0, 19, 600 << 10, 2 << 20} {
		body := bytes.Repeat([]byte{7}, size)
		if size > 1<<20 {
			clear(body[1152 : 1152*1000])
		}
		pr := newPair(t, body, frame.InternetPlaintext, func(s, r *Config) { s.SourcePipeline = true })
		ab := newPipe()
		dropped := false
		ab.filt = func(h frame.Header) (bool, time.Duration) {
			if h.Type == frame.TypeDATA && !dropped {
				dropped = true
				return true, 0
			}
			return false, 0
		}
		_, err := runUntil(pr, ab, newPipe(), 20*time.Second)
		pr.s.Close()
		pr.r.Close()
		if err != nil || pr.commits != 1 || !bytes.Equal(pr.dst.b, body) {
			t.Fatalf("size %d: %v commits %d", size, err, pr.commits)
		}
	}
}

func TestSourcePipelineBoundaries(t *testing.T) {
	body := make([]byte, 700001)
	for i := range body {
		body[i] = byte(i*7 + i>>11)
	}
	for _, mss := range []uint64{frame.InternetPlaintext, frame.DCPlaintext} {
		p := &Peer{cfg: Config{Size: uint64(len(body)), MSS: mss, SourcePipeline: true}, src: bytes.NewReader(body)}
		var first []byte
		for off := uint64(0); off < uint64(len(body)); {
			packet, err := p.classify(frame.Span{Start: off, End: uint64(len(body))}, false)
			if err != nil || !bytes.Equal(packet.buf, body[off:packet.sp.End]) {
				t.Fatalf("MSS %d offset %d: %v", mss, off, err)
			}
			if first == nil {
				first = packet.buf
			}
			off = packet.sp.End
		}
		if !bytes.Equal(first, body[:mss]) {
			t.Fatal("pending frame aliases recycled block")
		}
		p.Close()
	}
}

func TestSourcePipelineFailureAbortsTransfer(t *testing.T) {
	body := bytes.Repeat([]byte{7}, 600<<10)
	pr := newPair(t, body, frame.InternetPlaintext, func(s, r *Config) { s.SourcePipeline = true })
	pr.s.src = failingSource{body: body, failAt: sourceBlockSize / 1152 * 1152, short: true}
	_, err := runUntil(pr, newPipe(), newPipe(), 20*time.Second)
	pr.s.Close()
	pr.r.Close()
	if err == nil || pr.s.Reason() != frame.ReasonIO || pr.commits != 0 || pr.cleansS != 1 {
		t.Fatalf("error=%v reason=%d commits=%d cleanup=%d", err, pr.s.Reason(), pr.commits, pr.cleansS)
	}
}
