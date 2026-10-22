// streamlab exercises the local durable-stream prototype using synthetic data.
// It is not a network service and cannot accept real financial or medical data.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/afterdarksys/sahxfer/internal/streamlog"
)

func main() {
	n := flag.Int("records", 1024, "synthetic record count (1..65536)")
	size := flag.Int("record-bytes", 4096, "synthetic payload bytes (8..1048576)")
	batch := flag.Int("batch", 64, "records per durable batch (1..1024)")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "streamlab: unexpected argument")
		os.Exit(1)
	}
	if err := run(os.Stdout, *n, *size, *batch); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func payload(seq uint64, size int) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint64(b, seq)
	for i := 8; i < len(b); i++ {
		b[i] = byte(seq + uint64(i)*7)
	}
	return b
}

func run(out io.Writer, n, size, batch int) error {
	limits := streamlog.DefaultLimits()
	if n < 1 || n > 65536 || size < 8 || size > limits.MaxPayload || batch < 1 || batch > 1024 || batch > limits.MaxBatchBytes/(size+4) || uint64(n)*uint64(size+4)+uint64(n)*224 > limits.MaxBytes {
		return errors.New("streamlab: workload exceeds prototype bounds")
	}
	dir, err := os.MkdirTemp("", "sahxfer-streamlab-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	sourcePath, sinkPath := filepath.Join(dir, "outbox"), filepath.Join(dir, "sink")
	if err := os.Mkdir(sourcePath, 0700); err != nil {
		return err
	}
	if err := os.Mkdir(sinkPath, 0700); err != nil {
		return err
	}
	id := streamlog.Identity{Tenant: "synthetic", Stream: "processed-events", Partition: "0", Schema: "opaque-v1"}
	source, err := streamlog.Open(sourcePath, id, limits)
	if err != nil {
		return err
	}
	defer func() { source.Close() }()
	sink, err := streamlog.Open(sinkPath, id, limits)
	if err != nil {
		return err
	}
	defer func() { sink.Close() }()
	ctx := context.Background()
	started := time.Now()
	if _, err := source.Fence(ctx, 1); err != nil {
		return err
	}
	if _, err := sink.Fence(ctx, 1); err != nil {
		return err
	}
	duplicates := 0
	replayed := 0
	for first := 1; first <= n; first += batch {
		count := min(batch, n-first+1)
		body := make([][]byte, count)
		for i := range body {
			body[i] = payload(uint64(first+i), size)
		}
		if _, err := source.Append(ctx, 1, uint64(first), body); err != nil {
			return err
		}
		// Sender reads its durable outbox rather than relying on the caller's
		// still-live buffers. No outbox eviction is implemented in this release.
		records, err := source.Replay(1, uint64(first), count)
		if err != nil {
			return err
		}
		for i := range records {
			body[i] = records[i].Payload
		}
		if _, err := sink.Append(ctx, 1, uint64(first), body); err != nil {
			return err
		}
		if first == 1 {
			// Persist happened, but the producer did not observe the receipt.
			if err := sink.Close(); err != nil {
				return err
			}
			sink, err = streamlog.Open(sinkPath, id, limits)
			if err != nil {
				return err
			}
			r, err := sink.Append(ctx, 1, uint64(first), body)
			if err != nil || !r.Duplicate {
				return errors.New("streamlab: lost-ack retry failed")
			}
			duplicates++
		}
		consume := func() error {
			page, err := sink.Replay(1, uint64(first), count)
			if err != nil {
				return err
			}
			if len(page) != count {
				return errors.New("streamlab: missing records")
			}
			for _, r := range page {
				if !bytes.Equal(r.Payload, payload(r.Sequence, size)) {
					return errors.New("streamlab: integrity failure")
				}
			}
			replayed += len(page)
			return nil
		}
		if err := consume(); err != nil {
			return err
		}
		if first == 1 {
			// Consumer verification happened, but no processed cursor persisted.
			if err := sink.Close(); err != nil {
				return err
			}
			sink, err = streamlog.Open(sinkPath, id, limits)
			if err != nil {
				return err
			}
			if sink.State().Processed != 0 {
				return errors.New("streamlab: optimistic processed cursor")
			}
			if err := consume(); err != nil {
				return err
			}
		}
		if _, err := sink.CheckpointProcessed(ctx, 1, uint64(first+count-1)); err != nil {
			return err
		}
	}
	state := sink.State()
	if err := sink.Close(); err != nil {
		return err
	}
	sink, err = streamlog.Open(sinkPath, id, limits)
	if err != nil {
		return err
	}
	if sink.State() != state || state.Persisted != uint64(n) || state.Processed != uint64(n) {
		return errors.New("streamlab: restart state mismatch")
	}
	return json.NewEncoder(out).Encode(struct {
		Mode         string `json:"mode"`
		Records      int    `json:"records"`
		Bytes        int64  `json:"bytes"`
		Persisted    uint64 `json:"persisted"`
		Processed    uint64 `json:"processed"`
		Replayed     int    `json:"replayed_records"`
		Duplicates   int    `json:"duplicate_batches"`
		Transactions uint64 `json:"sink_transactions"`
		Millis       int64  `json:"elapsed_ms"`
	}{"local-synthetic-durable", n, int64(n) * int64(size), state.Persisted, state.Processed, replayed, duplicates, state.Transaction, time.Since(started).Milliseconds()})
}
