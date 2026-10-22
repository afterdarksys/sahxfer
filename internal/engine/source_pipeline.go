package engine

import "io"

const sourceBlockSize = 256 << 10

type sourceBlock struct {
	buf []byte
	off uint64
	err error
}

// One request and one result, with at most one read outstanding. The engine
// transfers buffer ownership to the worker and takes it back with the result.
// The worker never touches Peer, cipher state, or the active source buffer.
type sourcePipeline struct {
	requests chan sourceBlock
	results  chan sourceBlock
	done     chan struct{}
	pending  bool // engine-owned
}

func newSourcePipeline(src io.ReaderAt) *sourcePipeline {
	p := &sourcePipeline{
		requests: make(chan sourceBlock, 1),
		results:  make(chan sourceBlock, 1),
		done:     make(chan struct{}),
	}
	go func() {
		defer close(p.done)
		for b := range p.requests {
			b.err = readFullAt(src, b.buf, int64(b.off))
			p.results <- b
		}
	}()
	return p
}

func (p *sourcePipeline) close() {
	close(p.requests)
	<-p.done
	if p.pending {
		b := <-p.results
		clear(b.buf[:cap(b.buf)])
		p.pending = false
	}
}

func (p *Peer) readPipelinedSource(dst []byte, off uint64) error {
	if p.sourcePipe == nil {
		p.sourcePipe = newSourcePipeline(p.src)
	}
	pipe := p.sourcePipe
	// Round down to whole frames, preserving the existing classification offsets.
	blockSize := uint64(sourceBlockSize) / p.cfg.MSS * p.cfg.MSS
	n := min(blockSize, p.cfg.Size-off)
	b := sourceBlock{}
	hadPending := pipe.pending
	if hadPending {
		b = <-pipe.results
		pipe.pending = false
	} else {
		b.buf = make([]byte, sourceBlockSize)
	}
	if !hadPending || b.off != off || uint64(len(b.buf)) != n {
		b.off, b.buf = off, b.buf[:n]
		b.err = readFullAt(p.src, b.buf, int64(off))
	}
	if b.err != nil {
		clear(b.buf[:cap(b.buf)])
		return b.err
	}
	old := p.sourceBuf
	p.sourceBuf, p.sourceAt = b.buf, off
	if next := off + n; next < p.cfg.Size {
		if old == nil {
			old = make([]byte, sourceBlockSize)
		}
		pipe.requests <- sourceBlock{buf: old[:min(blockSize, p.cfg.Size-next)], off: next}
		pipe.pending = true
	} else {
		clear(old[:cap(old)])
	}
	copy(dst, p.sourceBuf[:len(dst)])
	return nil
}
