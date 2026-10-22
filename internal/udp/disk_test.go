package udp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/safeio"
)

// Includes both source hash passes, real file writes, fsync and rename.
// Source creation and independent destination verification are untimed.
// This is a local warm-cache benchmark, not a WAN or cold-storage claim.
func BenchmarkDiskTransfer(b *testing.B) {
	for _, pipeline := range []bool{false, true} {
		b.Run(fmt.Sprintf("pipeline=%t", pipeline), func(b *testing.B) { benchmarkDiskTransfer(b, pipeline, "internet", 30_000_000, 60*time.Second) })
	}
}

// BenchmarkSustainedTransfer is opt-in: large fixtures must never surprise a
// routine benchmark run. The fixture and verification use bounded memory.
func BenchmarkSustainedTransfer(b *testing.B) {
	raw := os.Getenv("SAHXFER_BENCH_BYTES")
	if raw == "" {
		b.Skip("set SAHXFER_BENCH_BYTES to opt into sustained transfers")
	}
	size, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || size <= 0 {
		b.Fatal("SAHXFER_BENCH_BYTES must be a positive int64")
	}
	timeout := 10 * time.Minute
	if raw := os.Getenv("SAHXFER_BENCH_TIMEOUT"); raw != "" {
		timeout, err = time.ParseDuration(raw)
		if err != nil || timeout <= 0 {
			b.Fatal("SAHXFER_BENCH_TIMEOUT must be a positive duration")
		}
	}
	for _, profile := range []string{"internet", "dc"} {
		for _, pipeline := range []bool{false, true} {
			b.Run(fmt.Sprintf("profile=%s/pipeline=%t", profile, pipeline), func(b *testing.B) {
				benchmarkDiskTransfer(b, pipeline, profile, size, timeout)
			})
		}
	}
}

func benchmarkDiskTransfer(b *testing.B, pipeline bool, profile string, size int64, timeout time.Duration) {
	dir, err := filepath.EvalSymlinks(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(dir, "source")
	fixture, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		b.Fatal(err)
	}
	_, writeErr := io.CopyN(fixture, rand.Reader, size)
	closeErr := fixture.Close()
	if writeErr != nil || closeErr != nil {
		b.Fatalf("fixture: write=%v close=%v", writeErr, closeErr)
	}

	root, err := safeio.OpenRoot(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer root.Close()
	b.SetBytes(size)
	b.ReportAllocs()
	var prepTotal, attachTotal, setupTotal, transferTotal, commitTotal, closeTotal time.Duration
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
			prepared := time.Now()
			key, token := testMaterial()
			cfg := engine.Config{Profile: profile, SourcePipeline: pipeline, Size: uint64(size), Key: key, Token: token, TransferID: 7, Sender: true, LocalDir: 0, PeerDir: 1, HaveHash: true, ExpectHash: sum}
			s, err := engine.New(cfg)
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			attachStart := time.Now()
			if err := s.AttachSource(src); err != nil {
				b.Fatal(err)
			}
			attached := time.Now()
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
			var commitStart, commitEnd time.Time
			r.SetHooks(engine.Hooks{Commit: func() error {
				commitStart = time.Now()
				err := tmp.Commit(true)
				commitEnd = time.Now()
				return err
			}, Cleanup: func() { _ = tmp.Remove() }})
			lc := listen(b)
			defer lc.Close()
			dc := dial(b, lc.LocalAddr())
			defer dc.Close()
			rxRcv, rxSnd := TuneBuffers(lc, WantBuffer)
			txRcv, txSnd := TuneBuffers(dc, WantBuffer)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			networkStart := time.Now()
			pprof.Do(ctx, pprof.Labels("phase", "network-and-commit"), func(ctx context.Context) {
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
			})
			finished := time.Now()
			elapsed := finished.Sub(started)
			b.StopTimer()
			// Receiving errs synchronizes access to the receiver's commit timestamps.
			if commitStart.IsZero() || commitEnd.IsZero() {
				b.Fatal("transfer returned without durable commit")
			}
			prepTotal += prepared.Sub(started)
			attachTotal += attached.Sub(attachStart)
			setupTotal += attachStart.Sub(prepared) + networkStart.Sub(attached)
			transferTotal += commitStart.Sub(networkStart)
			commitTotal += commitEnd.Sub(commitStart)
			closeTotal += finished.Sub(commitEnd)
			target, err := os.Open(filepath.Join(dir, "target"))
			if err != nil {
				b.Fatal(err)
			}
			verify := sha256.New()
			n, readErr := io.Copy(verify, target)
			closeErr := target.Close()
			var got [32]byte
			copy(got[:], verify.Sum(nil))
			if readErr != nil || closeErr != nil || n != size || got != sum {
				b.Fatalf("destination verification: bytes=%d read=%v close=%v digest_match=%t", n, readErr, closeErr, got == sum)
			}
			b.Logf("socket buffers: receiver rcv=%d snd=%d sender rcv=%d snd=%d", rxRcv, rxSnd, txRcv, txSnd)
			b.Logf("%d bytes profile=%s including preparation and commit: %v (%.1f MB/s)", size, profile, elapsed, float64(size)/elapsed.Seconds()/1e6)
			b.StartTimer()
		}()
	}
	b.StopTimer()
	for name, elapsed := range map[string]time.Duration{
		"prepare-ns/op": prepTotal, "attach-ns/op": attachTotal,
		"setup-ns/op": setupTotal, "transfer-ns/op": transferTotal,
		"commit-ns/op": commitTotal, "close-ns/op": closeTotal,
	} {
		b.ReportMetric(float64(elapsed)/float64(b.N), name)
	}
	b.ReportMetric(float64(size)*float64(b.N)/transferTotal.Seconds()/1e6, "transfer-MB/s")
}
