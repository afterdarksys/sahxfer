package streamlog

import "encoding/binary"

// Event is durable local operation metadata. It omits payloads and does not
// purport to be an externally anchored, signed audit event.
type Event struct {
	Transaction          uint64
	Operation            string
	Epoch, FirstSequence uint64
	Records              uint32
	ChainHead            [32]byte
}

// Audit returns bounded metadata for committed operations, verifying each
// segment on disk. Missing history is explicit, never skipped.
func (l *Log) Audit(first uint64, limit int) ([]Event, error) {
	if err := l.ready(); err != nil {
		return nil, err
	}
	if limit < 1 || limit > maxCount {
		return nil, ErrLimits
	}
	if first == 0 || first > uint64(len(l.segments))+1 {
		return nil, ErrGap
	}
	var out []Event
	for txn := first; txn <= uint64(len(l.segments)) && len(out) < limit; txn++ {
		b, err := l.committed(txn)
		if err != nil {
			return nil, err
		}
		op := ""
		switch b[8] {
		case kindFence:
			op = "producer_fenced"
		case kindAppend:
			op = "records_persisted"
		case kindProcessed:
			op = "consumer_checkpoint"
		}
		out = append(out, Event{txn, op, binary.LittleEndian.Uint64(b[24:]), binary.LittleEndian.Uint64(b[32:]), binary.LittleEndian.Uint32(b[40:]), l.segments[txn-1]})
		clear(b)
	}
	return out, nil
}

type Capacity struct{ Bytes, Records, Transactions uint64 }

// Available reports admission credit. Exhaustion rejects writes; this prototype
// never evicts retained history to make space for a slow consumer.
func (l *Log) Available() (Capacity, error) {
	if err := l.ready(); err != nil {
		return Capacity{}, err
	}
	return Capacity{l.limits.MaxBytes - l.used, l.limits.MaxRecords - uint64(len(l.records)), l.limits.MaxTransactions - uint64(len(l.segments))}, nil
}
