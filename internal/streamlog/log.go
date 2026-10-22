// Package streamlog is an experimental, single-owner durable partition log.
// It accepts local operator authorization only; it is not a network protocol or
// grant validator. Payloads are opaque and stored unencrypted in 0600 files.
package streamlog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"unicode/utf8"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/safeio"
)

var (
	ErrCorrupt  = errors.New("streamlog: corrupt committed history")
	ErrIdentity = errors.New("streamlog: identity mismatch")
	ErrFenced   = errors.New("streamlog: producer fenced")
	ErrSequence = errors.New("streamlog: noncontiguous sequence")
	ErrConflict = errors.New("streamlog: conflicting duplicate")
	ErrCapacity = errors.New("streamlog: capacity exhausted")
	ErrGap      = errors.New("streamlog: replay position unavailable")
	ErrPoisoned = errors.New("streamlog: reopen required after I/O failure")
	ErrClosed   = errors.New("streamlog: closed")
	ErrLimits   = errors.New("streamlog: invalid limits or identity")
)

const (
	maxPayload     = 1 << 20
	maxBatch       = 8 << 20
	maxCount       = 1024
	headerSize     = 80
	trailerSize    = 32
	checkpointSize = 112
	kindFence      = 1
	kindAppend     = 2
	kindProcessed  = 3
	checkpointName = "checkpoint"
)

// Identity is opaque local configuration, not proof of authorization.
type Identity struct{ Tenant, Stream, Partition, Schema string }

type Limits struct {
	MaxPayload, MaxBatchBytes             int
	MaxRecords, MaxBytes, MaxTransactions uint64
}

func DefaultLimits() Limits {
	return Limits{maxPayload, maxBatch, 65536, 256 << 20, 100000}
}

func (v Limits) valid() bool {
	return v.MaxPayload > 0 && v.MaxPayload <= maxPayload && v.MaxBatchBytes >= v.MaxPayload+4 &&
		v.MaxBatchBytes <= maxBatch && v.MaxRecords > 0 && v.MaxRecords <= 1000000 &&
		v.MaxTransactions > 0 && v.MaxTransactions <= 1000000 && v.MaxBytes >= headerSize+trailerSize && v.MaxBytes <= 1<<40
}

// Receipt separates persisted records from caller-declared processed records.
// The chain head is local integrity evidence, not an independently signed proof.
type Receipt struct {
	Epoch, Persisted, Processed, Transaction uint64
	ChainHead                                [32]byte
	Duplicate                                bool
}

type Record struct {
	Epoch, Sequence uint64
	Payload         []byte
}
type ref struct {
	txn       uint64
	off, size int
	digest    [32]byte
}
type epochState struct {
	start            int
	count, processed uint64
}

// Log is single-owner. Close releases its exclusive directory lock. No method
// may run concurrently with another method on the same Log.
type Log struct {
	root        *safeio.Root
	id          [32]byte
	limits      Limits
	epoch, used uint64
	head        [32]byte
	segments    [][32]byte
	records     []ref
	epochs      map[uint64]*epochState
	poisoned    bool
	// Test-only faults at persistence barriers. They never appear in production
	// APIs, configuration, logs or environment-variable dispatch.
	hook  func(string) error
	write func(*os.File, []byte) (int, error)
}

func Open(dir string, identity Identity, limits Limits) (*Log, error) {
	if !limits.valid() {
		return nil, ErrLimits
	}
	for _, s := range []string{identity.Tenant, identity.Stream, identity.Partition, identity.Schema} {
		if len(s) == 0 || len(s) > 128 || !utf8.ValidString(s) {
			return nil, ErrLimits
		}
		for _, c := range s {
			if c < 32 || c == 127 {
				return nil, ErrLimits
			}
		}
	}
	h := sha256.New()
	h.Write([]byte("sahxfer-stream-identity-v1\n"))
	for _, s := range []string{identity.Tenant, identity.Stream, identity.Partition, identity.Schema} {
		var n [4]byte
		binary.LittleEndian.PutUint32(n[:], uint32(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	l := &Log{limits: limits, epochs: make(map[uint64]*epochState)}
	copy(l.id[:], h.Sum(nil))
	r, err := safeio.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	l.root = r
	ok := false
	defer func() {
		if !ok {
			_ = r.Close()
		}
	}()
	if err := r.LockExclusive(); err != nil {
		return nil, err
	}
	cp, err := l.read(checkpointName, checkpointSize)
	if isAbsent(err) {
		// Interrupted initialization may leave only the fixed checkpoint temp.
		// Never remove segments or infer a new history when the checkpoint is lost.
		if e := r.RemoveTemp(checkpointName, "xfr_stream_checkpoint"); e != nil {
			return nil, e
		}
		empty, e := r.Empty()
		if e != nil {
			return nil, e
		}
		// A missing checkpoint in a nonempty store must never reset history.
		if !empty {
			return nil, ErrCorrupt
		}
		if err := l.publish(context.Background(), checkpointName, l.checkpoint(0, [32]byte{}), "checkpoint"); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		if len(cp) != checkpointSize || string(cp[:8]) != "SAHSCPT1" || sha256.Sum256(cp[:80]) != [32]byte(cp[80:]) {
			return nil, ErrCorrupt
		}
		if [32]byte(cp[8:40]) != l.id {
			return nil, ErrIdentity
		}
		n := binary.LittleEndian.Uint64(cp[40:48])
		if n > limits.MaxTransactions {
			return nil, ErrCapacity
		}
		for txn := uint64(1); txn <= n; txn++ {
			segment, err := l.read(segmentName(txn), limits.MaxBatchBytes+headerSize+trailerSize)
			if err != nil {
				return nil, fmt.Errorf("%w: segment %d", ErrCorrupt, txn)
			}
			if err := l.recoverSegment(segment); err != nil {
				clear(segment)
				return nil, err
			}
			clear(segment)
		}
		if l.head != [32]byte(cp[48:80]) {
			return nil, ErrCorrupt
		}
	}
	// A process may have died after rename but before directory fsync. Before
	// returning duplicate receipts, make the recovered namespace durable.
	if err := r.Sync(); err != nil {
		return nil, err
	}
	ok = true
	return l, nil
}

func (l *Log) Close() error {
	if l == nil || l.root == nil {
		return nil
	}
	err := l.root.Close()
	l.root = nil
	return err
}

func (l *Log) ready() error {
	if l == nil || l.root == nil {
		return ErrClosed
	}
	if l.poisoned {
		return ErrPoisoned
	}
	return nil
}

func (l *Log) State() Receipt {
	r := Receipt{Epoch: l.epoch, Transaction: uint64(len(l.segments)), ChainHead: l.head}
	if e := l.epochs[l.epoch]; e != nil {
		r.Persisted, r.Processed = e.count, e.processed
	}
	return r
}

// Position includes the persisted and caller-declared processed frontier of a
// retained epoch, even after a newer producer is fenced in.
func (l *Log) Position(epoch uint64) (Receipt, error) {
	if err := l.ready(); err != nil {
		return Receipt{}, err
	}
	e := l.epochs[epoch]
	if e == nil {
		return Receipt{}, ErrGap
	}
	return Receipt{Epoch: epoch, Persisted: e.count, Processed: e.processed, Transaction: uint64(len(l.segments)), ChainHead: l.head}, nil
}

func (l *Log) Fence(ctx context.Context, epoch uint64) (Receipt, error) {
	if err := l.ready(); err != nil {
		return Receipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if epoch == 0 || epoch < l.epoch {
		return Receipt{}, ErrFenced
	}
	if epoch == l.epoch {
		r := l.State()
		r.Duplicate = true
		return r, nil
	}
	return l.transact(ctx, kindFence, epoch, 0, 0, nil)
}

func (l *Log) Append(ctx context.Context, epoch, first uint64, payloads [][]byte) (Receipt, error) {
	if err := l.ready(); err != nil {
		return Receipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if epoch == 0 || epoch != l.epoch {
		return Receipt{}, ErrFenced
	}
	if len(payloads) == 0 || len(payloads) > maxCount {
		return Receipt{}, ErrLimits
	}
	if first == 0 || first > math.MaxUint64-uint64(len(payloads))+1 {
		return Receipt{}, ErrSequence
	}
	size := 0
	for _, p := range payloads {
		if len(p) > l.limits.MaxPayload {
			return Receipt{}, ErrLimits
		}
		size += 4 + len(p)
		if size > l.limits.MaxBatchBytes {
			return Receipt{}, ErrLimits
		}
	}
	e := l.epochs[epoch]
	last := first + uint64(len(payloads)) - 1
	if first <= e.count {
		if last > e.count {
			return Receipt{}, ErrSequence
		}
		var checked uint64
		for i, p := range payloads {
			r := l.records[e.start+int(first)-1+i]
			if r.size != len(p) || r.digest != sha256.Sum256(p) {
				return Receipt{}, ErrConflict
			}
			if checked != r.txn {
				b, err := l.committed(r.txn)
				clear(b)
				if err != nil {
					return Receipt{}, err
				}
				checked = r.txn
			}
		}
		r := l.State()
		r.Duplicate = true
		return r, nil
	}
	if first != e.count+1 {
		return Receipt{}, ErrSequence
	}
	if uint64(len(l.records))+uint64(len(payloads)) > l.limits.MaxRecords {
		return Receipt{}, ErrCapacity
	}
	body := make([]byte, size)
	off := 0
	for _, p := range payloads {
		binary.LittleEndian.PutUint32(body[off:], uint32(len(p)))
		off += 4
		copy(body[off:], p)
		off += len(p)
	}
	defer clear(body)
	return l.transact(ctx, kindAppend, epoch, first, uint32(len(payloads)), body)
}

// CheckpointProcessed persists a declaration by the caller. It does not execute
// or atomically commit the consumer's external side effects.
func (l *Log) CheckpointProcessed(ctx context.Context, epoch, sequence uint64) (Receipt, error) {
	if err := l.ready(); err != nil {
		return Receipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	e := l.epochs[epoch]
	if e == nil {
		return Receipt{}, ErrGap
	}
	if sequence < e.processed || sequence > e.count {
		return Receipt{}, ErrSequence
	}
	if sequence == e.processed {
		r, _ := l.Position(epoch)
		r.Duplicate = true
		return r, nil
	}
	return l.transact(ctx, kindProcessed, epoch, sequence, 0, nil)
}

func (l *Log) transact(ctx context.Context, kind byte, epoch, seq uint64, count uint32, body []byte) (Receipt, error) {
	size := headerSize + len(body) + trailerSize
	if uint64(len(l.segments)) >= l.limits.MaxTransactions || uint64(size) > l.limits.MaxBytes-l.used {
		return Receipt{}, ErrCapacity
	}
	txn := uint64(len(l.segments)) + 1
	b := make([]byte, size)
	defer clear(b)
	copy(b, "SAHSLOG1")
	b[8] = kind
	binary.LittleEndian.PutUint64(b[16:], txn)
	binary.LittleEndian.PutUint64(b[24:], epoch)
	binary.LittleEndian.PutUint64(b[32:], seq)
	binary.LittleEndian.PutUint32(b[40:], count)
	binary.LittleEndian.PutUint32(b[44:], uint32(len(body)))
	copy(b[48:], l.head[:])
	copy(b[headerSize:], body)
	head := sha256.Sum256(b[:size-trailerSize])
	copy(b[size-trailerSize:], head[:])
	if err := l.publish(ctx, segmentName(txn), b, "segment"); err != nil {
		l.poisoned = true
		return Receipt{}, err
	}
	if err := l.publish(ctx, checkpointName, l.checkpoint(txn, head), "checkpoint"); err != nil {
		l.poisoned = true
		return Receipt{}, err
	}
	if err := l.recoverSegment(b); err != nil {
		l.poisoned = true
		return Receipt{}, err
	}
	return l.Position(epoch)
}

func (l *Log) checkpoint(txn uint64, head [32]byte) []byte {
	b := make([]byte, checkpointSize)
	copy(b, "SAHSCPT1")
	copy(b[8:], l.id[:])
	binary.LittleEndian.PutUint64(b[40:], txn)
	copy(b[48:], head[:])
	digest := sha256.Sum256(b[:80])
	copy(b[80:], digest[:])
	return b
}

func segmentName(txn uint64) string { return fmt.Sprintf("segment-%020d", txn) }

func isAbsent(err error) bool { var c *code.Error; return errors.As(err, &c) && c.C == "not_found" }

func (l *Log) read(name string, max int) ([]byte, error) {
	f, err := l.root.OpenRegular(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() < 0 || st.Size() > int64(max) {
		return nil, ErrCorrupt
	}
	b := make([]byte, int(st.Size()))
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, ErrCorrupt
	}
	return b, nil
}

func (l *Log) publish(ctx context.Context, name string, b []byte, label string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	id := "xfr_stream_" + label
	if err := l.root.RemoveTemp(name, id); err != nil {
		return err
	}
	t, err := l.root.CreateTemp(name, id, true)
	if err != nil {
		return err
	}
	defer t.Remove()
	n := 0
	if l.write != nil {
		n, err = l.write(t.File, b)
	} else {
		n, err = t.File.Write(b)
	}
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	if err := l.barrier(label + "_written"); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := t.Commit(true); err != nil {
		return err
	}
	if err := l.barrier(label + "_renamed"); err != nil {
		return err
	}
	if err := l.root.Sync(); err != nil {
		return err
	}
	return l.barrier(label + "_durable")
}

func (l *Log) barrier(stage string) error {
	if l.hook != nil {
		return l.hook(stage)
	}
	return nil
}

// recoverSegment validates before changing any state. Quotas bound both parsing
// and the retained metadata index; invalid history is never partially applied.
func (l *Log) recoverSegment(b []byte) error {
	if len(b) < headerSize+trailerSize || len(b) > l.limits.MaxBatchBytes+headerSize+trailerSize {
		return ErrCorrupt
	}
	end := len(b) - trailerSize
	digest := sha256.Sum256(b[:end])
	if string(b[:8]) != "SAHSLOG1" || !bytes.Equal(b[9:16], make([]byte, 7)) || digest != [32]byte(b[end:]) || [32]byte(b[48:80]) != l.head {
		return ErrCorrupt
	}
	txn := binary.LittleEndian.Uint64(b[16:])
	epoch := binary.LittleEndian.Uint64(b[24:])
	seq := binary.LittleEndian.Uint64(b[32:])
	count := binary.LittleEndian.Uint32(b[40:])
	size := binary.LittleEndian.Uint32(b[44:])
	if txn != uint64(len(l.segments))+1 || int(size) != end-headerSize || epoch == 0 || count > maxCount {
		return ErrCorrupt
	}
	if txn > l.limits.MaxTransactions || uint64(len(b)) > l.limits.MaxBytes-l.used {
		return ErrCapacity
	}
	e := l.epochs[epoch]
	var refs []ref
	switch b[8] {
	case kindFence:
		if epoch <= l.epoch || seq != 0 || count != 0 || size != 0 {
			return ErrCorrupt
		}
	case kindProcessed:
		if e == nil || seq <= e.processed || seq > e.count || count != 0 || size != 0 {
			return ErrCorrupt
		}
	case kindAppend:
		if epoch != l.epoch || e == nil || count == 0 || seq != e.count+1 {
			return ErrCorrupt
		}
		if uint64(len(l.records))+uint64(count) > l.limits.MaxRecords {
			return ErrCapacity
		}
		off := headerSize
		for i := uint32(0); i < count; i++ {
			if off+4 > end {
				return ErrCorrupt
			}
			raw := binary.LittleEndian.Uint32(b[off:])
			off += 4
			if raw > uint32(l.limits.MaxPayload) || uint64(raw) > uint64(end-off) {
				return ErrCorrupt
			}
			n := int(raw)
			refs = append(refs, ref{txn, off, n, sha256.Sum256(b[off : off+n])})
			off += n
		}
		if off != end {
			return ErrCorrupt
		}
	default:
		return ErrCorrupt
	}
	switch b[8] {
	case kindFence:
		l.epoch = epoch
		l.epochs[epoch] = &epochState{start: len(l.records)}
	case kindProcessed:
		e.processed = seq
	case kindAppend:
		l.records = append(l.records, refs...)
		e.count += uint64(count)
	}
	l.used += uint64(len(b))
	l.head = digest
	l.segments = append(l.segments, digest)
	return nil
}

// Replay returns an owned, bounded page. An empty page means exactly one past
// the persisted tail, not a silently skipped missing range.
func (l *Log) Replay(epoch, first uint64, limit int) ([]Record, error) {
	if err := l.ready(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > maxCount {
		return nil, ErrLimits
	}
	e := l.epochs[epoch]
	if e == nil || first == 0 || first > e.count+1 {
		return nil, ErrGap
	}
	var out []Record
	var b []byte
	var txn uint64
	used := 0
	defer func() { clear(b) }()
	for seq := first; seq <= e.count && len(out) < limit; seq++ {
		r := l.records[e.start+int(seq)-1]
		if used+4+r.size > l.limits.MaxBatchBytes {
			break
		}
		if txn != r.txn {
			clear(b)
			var err error
			b, err = l.committed(r.txn)
			if err != nil {
				return nil, err
			}
			txn = r.txn
		}
		if r.off > len(b)-trailerSize-r.size {
			l.poisoned = true
			return nil, ErrCorrupt
		}
		out = append(out, Record{epoch, seq, append([]byte(nil), b[r.off:r.off+r.size]...)})
		used += 4 + r.size
	}
	return out, nil
}

func (l *Log) committed(txn uint64) ([]byte, error) {
	b, err := l.read(segmentName(txn), l.limits.MaxBatchBytes+headerSize+trailerSize)
	if err != nil || len(b) < headerSize+trailerSize || sha256.Sum256(b[:len(b)-trailerSize]) != l.segments[txn-1] || [32]byte(b[len(b)-trailerSize:]) != l.segments[txn-1] {
		clear(b)
		l.poisoned = true
		return nil, ErrCorrupt
	}
	return b, nil
}
