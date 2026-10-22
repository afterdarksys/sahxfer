package streamlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

var testID = Identity{"tenant", "stream", "partition", "opaque-v1"}
var bg = context.Background()

func directory(t testing.TB) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func openLog(t testing.TB, dir string, limits Limits) *Log {
	t.Helper()
	l, err := Open(dir, testID, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func prepare(t testing.TB, dir string) *Log {
	t.Helper()
	l := openLog(t, dir, DefaultLimits())
	if _, err := l.Fence(bg, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(bg, 1, 1, [][]byte{[]byte("one")}); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestPersistReplayFenceCheckpoint(t *testing.T) {
	dir := directory(t)
	l := prepare(t, dir)
	r, err := l.Append(bg, 1, 2, [][]byte{nil, []byte("three")})
	if err != nil || r.Persisted != 3 || r.Processed != 0 {
		t.Fatalf("receipt %+v: %v", r, err)
	}
	txn := r.Transaction
	r, err = l.Append(bg, 1, 1, [][]byte{[]byte("one"), nil, []byte("three")})
	if err != nil || !r.Duplicate || r.Transaction != txn {
		t.Fatalf("retry %+v: %v", r, err)
	}
	if _, err = l.Append(bg, 1, 1, [][]byte{[]byte("changed")}); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err = l.Append(bg, 1, 3, [][]byte{[]byte("three"), []byte("four")}); !errors.Is(err, ErrSequence) {
		t.Fatal(err)
	}
	if _, err = l.Append(bg, 1, 5, [][]byte{nil}); !errors.Is(err, ErrSequence) {
		t.Fatal(err)
	}
	if _, err = l.CheckpointProcessed(bg, 1, 4); !errors.Is(err, ErrSequence) {
		t.Fatal(err)
	}
	if _, err = l.CheckpointProcessed(bg, 1, 2); err != nil {
		t.Fatal(err)
	}
	if _, err = l.CheckpointProcessed(bg, 1, 1); !errors.Is(err, ErrSequence) {
		t.Fatal(err)
	}
	state := l.State()
	l.Close()
	l = openLog(t, dir, DefaultLimits())
	if l.State() != state {
		t.Fatalf("recovered %+v want %+v", l.State(), state)
	}
	records, err := l.Replay(1, 1, 10)
	if err != nil || len(records) != 3 || !bytes.Equal(records[2].Payload, []byte("three")) {
		t.Fatalf("replay %v", err)
	}
	records[0].Payload[0] = 'X'
	again, _ := l.Replay(1, 1, 1)
	if string(again[0].Payload) != "one" {
		t.Fatal("replay aliases storage")
	}
	if _, err = l.Replay(1, 5, 1); !errors.Is(err, ErrGap) {
		t.Fatal(err)
	}
	if tail, err := l.Replay(1, 4, 1); err != nil || len(tail) != 0 {
		t.Fatal("tail")
	}
	if _, err = l.Fence(bg, 2); err != nil {
		t.Fatal(err)
	}
	if _, err = l.Append(bg, 1, 4, [][]byte{nil}); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	if receipt, e := l.CheckpointProcessed(bg, 1, 3); e != nil || receipt.Epoch != 1 || receipt.Processed != 3 {
		t.Fatalf("old consumer checkpoint: %+v %v", receipt, e)
	}
	if _, err = l.Fence(bg, 1); !errors.Is(err, ErrFenced) {
		t.Fatal(err)
	}
	if _, err = l.Append(bg, 2, 1, [][]byte{[]byte("new epoch")}); err != nil {
		t.Fatal(err)
	}
	if old, err := l.Replay(1, 3, 1); err != nil || string(old[0].Payload) != "three" {
		t.Fatal("old epoch history lost")
	}
	events, err := l.Audit(1, 10)
	if err != nil || len(events) != 7 || events[3].Operation != "consumer_checkpoint" {
		t.Fatalf("audit %+v %v", events, err)
	}
	l.Close()
	l = openLog(t, dir, DefaultLimits())
	old, e := l.Position(1)
	if e != nil || old.Processed != 3 || l.State().Epoch != 2 || l.State().Processed != 0 {
		t.Fatal("rollover mixed producer and consumer positions")
	}
}

func TestQuotasAndCancellation(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxRecords = 1
	l := openLog(t, directory(t), lim)
	l.Fence(bg, 1)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := l.Append(ctx, 1, 1, [][]byte{nil}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if l.poisoned || l.State().Persisted != 0 {
		t.Fatal("cancel changed state")
	}
	if _, err := l.Append(bg, 1, 1, [][]byte{nil}); err != nil {
		t.Fatal(err)
	}
	if c, _ := l.Available(); c.Records != 0 {
		t.Fatal(c)
	}
	if _, err := l.Append(bg, 1, 2, [][]byte{nil}); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	if r, err := l.Append(bg, 1, 1, [][]byte{nil}); err != nil || !r.Duplicate {
		t.Fatal("full store rejected retry")
	}
	if _, err := l.Append(bg, 1, 2, [][]byte{make([]byte, maxPayload+1)}); !errors.Is(err, ErrLimits) {
		t.Fatal(err)
	}
	if _, err := l.Append(bg, 1, ^uint64(0), [][]byte{nil, nil}); !errors.Is(err, ErrSequence) {
		t.Fatal(err)
	}
	lim = DefaultLimits()
	lim.MaxTransactions = 1
	m := openLog(t, directory(t), lim)
	m.Fence(bg, 1)
	if _, err := m.Append(bg, 1, 1, [][]byte{nil}); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
	lim = DefaultLimits()
	lim.MaxBytes = headerSize + trailerSize
	n := openLog(t, directory(t), lim)
	n.Fence(bg, 1)
	if _, err := n.Append(bg, 1, 1, [][]byte{nil}); !errors.Is(err, ErrCapacity) {
		t.Fatal(err)
	}
}

func TestIdentityLockAndPathRefusal(t *testing.T) {
	dir := directory(t)
	l := prepare(t, dir)
	if other, err := Open(dir, testID, DefaultLimits()); err == nil {
		other.Close()
		t.Fatal("second writer acquired lock")
	}
	l.Close()
	id := testID
	id.Tenant = "other"
	if other, err := Open(dir, id, DefaultLimits()); !errors.Is(err, ErrIdentity) {
		if other != nil {
			other.Close()
		}
		t.Fatal(err)
	}
	link := filepath.Join(directory(t), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(link, testID, DefaultLimits()); err == nil {
		other.Close()
		t.Fatal("symlink root accepted")
	}
	if other, err := Open(dir+"/../escape", testID, DefaultLimits()); err == nil {
		other.Close()
		t.Fatal("path escape accepted")
	}
	checkpoint := filepath.Join(dir, checkpointName)
	if err := os.Rename(checkpoint, checkpoint+".saved"); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(dir, testID, DefaultLimits()); err == nil {
		other.Close()
		t.Fatal("missing checkpoint reset history")
	}
	if err := os.Symlink(checkpoint+".saved", checkpoint); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(dir, testID, DefaultLimits()); err == nil {
		other.Close()
		t.Fatal("symlink checkpoint accepted")
	}
}

func TestCommittedCorruptionFailsClosed(t *testing.T) {
	for _, target := range []string{checkpointName, segmentName(1), segmentName(2)} {
		for _, truncate := range []bool{false, true} {
			dir := directory(t)
			l := prepare(t, dir)
			l.Close()
			path := filepath.Join(dir, target)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if truncate {
				b = b[:len(b)-1]
			} else {
				b[len(b)/2] ^= 1
			}
			if err := os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if other, err := Open(dir, testID, DefaultLimits()); !errors.Is(err, ErrCorrupt) {
				if other != nil {
					other.Close()
				}
				t.Fatalf("%s: %v", target, err)
			}
		}
	}
	dir := directory(t)
	l := prepare(t, dir)
	path := filepath.Join(dir, segmentName(2))
	if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Replay(1, 1, 1); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
	if _, err := l.Append(bg, 1, 2, [][]byte{nil}); !errors.Is(err, ErrPoisoned) {
		t.Fatal(err)
	}
}

func TestWriteFailuresNeverAcknowledge(t *testing.T) {
	for _, short := range []bool{false, true} {
		dir := directory(t)
		l := prepare(t, dir)
		l.write = func(f *os.File, b []byte) (int, error) {
			f.Write(b[:1])
			if short {
				return 1, nil
			}
			return 1, syscall.ENOSPC
		}
		r, err := l.Append(bg, 1, 2, [][]byte{[]byte("two")})
		if err == nil || r != (Receipt{}) || l.State().Persisted != 1 {
			t.Fatal("failed write acknowledged")
		}
		if short && !errors.Is(err, io.ErrShortWrite) {
			t.Fatal(err)
		}
		if _, err := l.Append(bg, 1, 2, [][]byte{nil}); !errors.Is(err, ErrPoisoned) {
			t.Fatal(err)
		}
		l.Close()
		l = openLog(t, dir, DefaultLimits())
		if l.State().Persisted != 1 {
			t.Fatal("partial tail committed")
		}
	}
}

func TestFailureAtPersistenceBarriers(t *testing.T) {
	for _, stage := range []string{"segment_written", "segment_renamed", "segment_durable", "checkpoint_written", "checkpoint_renamed", "checkpoint_durable"} {
		t.Run(stage, func(t *testing.T) {
			dir := directory(t)
			l := prepare(t, dir)
			l.hook = func(s string) error {
				if s == stage {
					return syscall.EIO
				}
				return nil
			}
			r, err := l.Append(bg, 1, 2, [][]byte{[]byte("two")})
			if err == nil || r != (Receipt{}) {
				t.Fatal("failure acknowledged")
			}
			l.Close()
			l = openLog(t, dir, DefaultLimits())
			want := uint64(1)
			if stage == "checkpoint_renamed" || stage == "checkpoint_durable" {
				want = 2
			}
			if l.State().Persisted != want {
				t.Fatalf("recovery %d want %d", l.State().Persisted, want)
			}
			r, err = l.Append(bg, 1, 2, [][]byte{[]byte("two")})
			if err != nil || r.Persisted != 2 || r.Duplicate != (want == 2) {
				t.Fatalf("retry %+v %v", r, err)
			}
		})
	}
}

// Exit from inside a persistence barrier: no deferred file cleanup or Close.
// This exercises process death; it is not a power-loss/filesystem fault model.
func TestCrashHelper(t *testing.T) {
	dir := os.Getenv("SAHXFER_TEST_CRASH_DIR")
	if dir == "" {
		return
	}
	l, err := Open(dir, testID, DefaultLimits())
	if err != nil {
		os.Exit(74)
	}
	l.hook = func(stage string) error {
		if stage == os.Getenv("SAHXFER_TEST_CRASH_STAGE") {
			os.Exit(73)
		}
		return nil
	}
	l.Append(bg, 1, 2, [][]byte{[]byte("two")})
	os.Exit(75)
}

func TestProcessCrashRecovery(t *testing.T) {
	for _, stage := range []string{"segment_written", "segment_renamed", "segment_durable", "checkpoint_written", "checkpoint_renamed", "checkpoint_durable"} {
		t.Run(stage, func(t *testing.T) {
			dir := directory(t)
			l := prepare(t, dir)
			l.Close()
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelper$")
			cmd.Env = append(os.Environ(), "SAHXFER_TEST_CRASH_DIR="+dir, "SAHXFER_TEST_CRASH_STAGE="+stage)
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("child: %v", err)
			}
			l = openLog(t, dir, DefaultLimits())
			if _, err := l.Append(bg, 1, 2, [][]byte{[]byte("two")}); err != nil {
				t.Fatal(err)
			}
			records, err := l.Replay(1, 1, 10)
			if err != nil || len(records) != 2 || string(records[0].Payload) != "one" || string(records[1].Payload) != "two" {
				t.Fatal("acknowledged history lost or duplicated")
			}
		})
	}
}

func TestRecoveryParserRejectsResignedInvalidFields(t *testing.T) {
	dir := directory(t)
	prepare(t, dir)
	original, err := os.ReadFile(filepath.Join(dir, segmentName(1)))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[8] = 255 }, func(b []byte) { b[9] = 1 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[40:], ^uint32(0)) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[44:], ^uint32(0)) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[16:], 2) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[24:], 0) },
	} {
		b := append([]byte(nil), original...)
		mutate(b)
		sum := sha256.Sum256(b[:len(b)-32])
		copy(b[len(b)-32:], sum[:])
		p := &Log{limits: DefaultLimits(), epochs: make(map[uint64]*epochState)}
		if err := p.recoverSegment(b); !errors.Is(err, ErrCorrupt) {
			t.Fatal(err)
		}
	}
}

func TestFenceAndConsumerCheckpointRecovery(t *testing.T) {
	for _, fence := range []bool{false, true} {
		for _, stage := range []string{"segment_written", "checkpoint_durable"} {
			dir := directory(t)
			l := prepare(t, dir)
			l.hook = func(s string) error {
				if s == stage {
					return syscall.EIO
				}
				return nil
			}
			var err error
			if fence {
				_, err = l.Fence(bg, 2)
			} else {
				_, err = l.CheckpointProcessed(bg, 1, 1)
			}
			if err == nil {
				t.Fatal("fault did not fire")
			}
			l.Close()
			l = openLog(t, dir, DefaultLimits())
			if fence {
				want := uint64(1)
				if stage == "checkpoint_durable" {
					want = 2
				}
				if l.State().Epoch != want {
					t.Fatal("fence recovery")
				}
			} else {
				want := uint64(0)
				if stage == "checkpoint_durable" {
					want = 1
				}
				if l.State().Processed != want {
					t.Fatal("consumer checkpoint recovery")
				}
			}
		}
	}
}

func TestInterruptedInitializationAndSymlinkSegment(t *testing.T) {
	dir := directory(t)
	if err := os.WriteFile(filepath.Join(dir, ".sahxfer-xfr_stream_checkpoint.part"), []byte("torn"), 0600); err != nil {
		t.Fatal(err)
	}
	l := prepare(t, dir)
	l.Close()
	p := filepath.Join(dir, segmentName(2))
	if err := os.Rename(p, p+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(p+".saved", p); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(dir, testID, DefaultLimits()); err == nil {
		other.Close()
		t.Fatal("symlink segment accepted")
	}
}

func TestDuplicateRejectsOnDiskCorruption(t *testing.T) {
	dir := directory(t)
	l := prepare(t, dir)
	if err := os.WriteFile(filepath.Join(dir, segmentName(2)), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(bg, 1, 1, [][]byte{[]byte("one")}); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
}

func TestReplayPageBound(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxPayload = 128
	limits.MaxBatchBytes = 132
	l := openLog(t, directory(t), limits)
	l.Fence(bg, 1)
	for i := uint64(1); i <= 3; i++ {
		if _, err := l.Append(bg, 1, i, [][]byte{make([]byte, 128)}); err != nil {
			t.Fatal(err)
		}
	}
	if page, err := l.Replay(1, 1, 3); err != nil || len(page) != 1 {
		t.Fatalf("page %d: %v", len(page), err)
	}
}

func TestCancellationBetweenDurabilityBarriers(t *testing.T) {
	dir := directory(t)
	l := prepare(t, dir)
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	l.hook = func(stage string) error {
		if stage == "segment_durable" {
			cancel()
		}
		return nil
	}
	if r, err := l.Append(ctx, 1, 2, [][]byte{nil}); !errors.Is(err, context.Canceled) || r != (Receipt{}) {
		t.Fatalf("%+v %v", r, err)
	}
	l.Close()
	l = openLog(t, dir, DefaultLimits())
	if l.State().Persisted != 1 {
		t.Fatal("cancel advanced checkpoint")
	}
}

func TestInvalidIdentityAndLimits(t *testing.T) {
	id := testID
	id.Tenant = string([]byte{255})
	if l, err := Open(directory(t), id, DefaultLimits()); !errors.Is(err, ErrLimits) {
		if l != nil {
			l.Close()
		}
		t.Fatal(err)
	}
	if l, err := Open(directory(t), testID, Limits{}); !errors.Is(err, ErrLimits) {
		if l != nil {
			l.Close()
		}
		t.Fatal(err)
	}
}

func TestOversizedEncodedPayloadFailsBeforeAllocation(t *testing.T) {
	b := make([]byte, headerSize+4+trailerSize)
	copy(b, "SAHSLOG1")
	b[8] = kindAppend
	binary.LittleEndian.PutUint64(b[16:], 1)
	binary.LittleEndian.PutUint64(b[24:], 1)
	binary.LittleEndian.PutUint64(b[32:], 1)
	binary.LittleEndian.PutUint32(b[40:], 1)
	binary.LittleEndian.PutUint32(b[44:], 4)
	binary.LittleEndian.PutUint32(b[80:], ^uint32(0))
	sum := sha256.Sum256(b[:len(b)-trailerSize])
	copy(b[len(b)-trailerSize:], sum[:])
	l := &Log{epoch: 1, limits: DefaultLimits(), epochs: map[uint64]*epochState{1: {}}}
	if err := l.recoverSegment(b); !errors.Is(err, ErrCorrupt) {
		t.Fatal(err)
	}
}

func FuzzRecoveryParser(f *testing.F) {
	f.Add([]byte("SAHSLOG1"))
	f.Add(make([]byte, 112))
	seed := make([]byte, 112)
	copy(seed, "SAHSLOG1")
	seed[8] = kindFence
	binary.LittleEndian.PutUint64(seed[16:], 1)
	binary.LittleEndian.PutUint64(seed[24:], 1)
	digest := sha256.Sum256(seed[:80])
	copy(seed[80:], digest[:])
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		l := &Log{limits: DefaultLimits(), epochs: make(map[uint64]*epochState)}
		_ = l.recoverSegment(b)
		// Also exercise semantic parsing, not only the checksum rejection gate.
		if len(b) >= headerSize+trailerSize && len(b) <= maxBatch+headerSize+trailerSize {
			b = append([]byte(nil), b...)
			digest := sha256.Sum256(b[:len(b)-trailerSize])
			copy(b[len(b)-trailerSize:], digest[:])
			l = &Log{limits: DefaultLimits(), epochs: make(map[uint64]*epochState)}
			_ = l.recoverSegment(b)
		}
	})
}
