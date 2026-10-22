package udp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/safeio"
)

// Includes both source hash passes, real file writes, fsync and rename.
// Source creation and independent destination verification are untimed.
// This is a local warm-cache benchmark, not a WAN or cold-storage claim.
func BenchmarkDiskTransfer(b *testing.B) {
	const size = 30_000_000
	body := make([]byte, size)
	for i := range body {
		body[i] = byte(i*7 + i>>11)
	}
	dir, err := filepath.EvalSymlinks(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(dir, "source")
	if err := os.WriteFile(path, body, 0600); err != nil {
		b.Fatal(err)
	}
	root, err := safeio.OpenRoot(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	b.SetBytes(size)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		func() {
			started := time.Now()
			src, err := os.Open(path)
			if err != nil {
				b.Fatal(err)
			}
			defer src.Close()
			h := sha256.New()
			if _, err := io.Copy(h, src); err != nil {
				b.Fatal(err)
			}
			var sum [32]byte
			copy(sum[:], h.Sum(nil))
			key, token := testMaterial()
			cfg := engine.Config{Size: size, Key: key, Token: token, TransferID: 7, Sender: true, LocalDir: 0, PeerDir: 1, HaveHash: true, ExpectHash: sum}
			s, err := engine.New(cfg)
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			if err := s.AttachSource(src); err != nil {
				b.Fatal(err)
			}
			cfg.Sender, cfg.LocalDir, cfg.PeerDir = false, 1, 0
			r, err := engine.New(cfg)
			if err != nil {
				b.Fatal(err)
			}
			defer r.Close()
			tmp, err := root.CreateTemp("target", fmt.Sprintf("xfr_bench%08d", i), true)
			if err != nil {
				b.Fatal(err)
			}
			defer tmp.Remove()
			r.AttachDest(tmp.File)
			r.SetHooks(engine.Hooks{Commit: func() error { return tmp.Commit(true) }, Cleanup: func() { _ = tmp.Remove() }})
			lc := listen(b)
			defer lc.Close()
			dc := dial(b, lc.LocalAddr())
			defer dc.Close()
			TuneBuffers(lc, WantBuffer)
			TuneBuffers(dc, WantBuffer)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			errs := make(chan error, 1)
			go func() { errs <- Run(ctx, Config{Peer: r, Conn: lc}) }()
			txerr := Run(ctx, Config{Peer: s, Conn: dc, Connected: true})
			if txerr != nil {
				cancel()
			}
			rxerr := <-errs
			if txerr != nil || rxerr != nil {
				b.Fatalf("tx=%v rx=%v", txerr, rxerr)
			}
			elapsed := time.Since(started)
			b.StopTimer()
			got, err := os.ReadFile(filepath.Join(dir, "target"))
			if err != nil || !bytes.Equal(got, body) {
				b.Fatalf("destination verification: %v", err)
			}
			b.Logf("30 MB including preparation and commit: %v (%.1f MB/s)", elapsed, size/elapsed.Seconds()/1e6)
			b.StartTimer()
		}()
	}
}
