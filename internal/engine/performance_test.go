package engine

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/frame"
)

// These isolate actual file I/O from network pacing. End-to-end timing
// must additionally include grant preparation, encryption, and commit.
func BenchmarkFileReceive(b *testing.B) {
	const size = 4 << 20
	f, err := os.CreateTemp(b.TempDir(), "receive")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	payload := bytes.Repeat([]byte{7}, frame.InternetPlaintext)
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, token := testMaterial()
		p, err := New(Config{Size: size, Key: key, Token: token, LocalDir: 1, PeerDir: 0})
		if err != nil {
			b.Fatal(err)
		}
		p.AttachDest(f)
		for off := uint64(0); off < size; {
			n := min(uint64(len(payload)), size-off)
			p.onData(time.Second, frame.Header{Offset: off, Seq: off + 1}, payload[:n])
			off += n
		}
		if p.Err() != nil || p.hashedTo != size {
			b.Fatalf("receive: %v, hashed %d", p.Err(), p.hashedTo)
		}
		p.Close()
	}
}

func BenchmarkFileSource(b *testing.B) {
	for _, pipeline := range []bool{false, true} {
		b.Run(fmt.Sprintf("pipeline=%t", pipeline), func(b *testing.B) { benchmarkFileSource(b, pipeline) })
	}
}

func benchmarkFileSource(b *testing.B, pipeline bool) {
	const size = 4 << 20
	f, err := os.CreateTemp(b.TempDir(), "source")
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(bytes.Repeat([]byte{7}, size)); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := &Peer{cfg: Config{Size: size, MSS: frame.InternetPlaintext, SourcePipeline: pipeline}, src: f}
		for off := uint64(0); off < size; {
			packet, err := p.classify(frame.Span{Start: off, End: size}, false)
			if err != nil {
				b.Fatal(err)
			}
			off = packet.sp.End
		}
		p.Close()
	}
}
