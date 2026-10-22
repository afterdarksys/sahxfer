package streamlog

import (
	"bytes"
	"fmt"
	"testing"
)

// Includes immutable segment publication and checkpoint publication with their
// file and directory syncs. Excludes creation, fencing, replay and networking.
func BenchmarkDurableAppend(b *testing.B) {
	for _, count := range []int{1, 64, 256} {
		b.Run(fmt.Sprintf("records=%d", count), func(b *testing.B) {
			limits := DefaultLimits()
			limits.MaxRecords = 1000000
			limits.MaxBytes = 1 << 40
			limits.MaxTransactions = 1000000
			l := openLog(b, directory(b), limits)
			if _, err := l.Fence(bg, 1); err != nil {
				b.Fatal(err)
			}
			body := make([][]byte, count)
			for i := range body {
				body[i] = bytes.Repeat([]byte{7}, 4096)
			}
			b.SetBytes(int64(count * 4096))
			b.ReportAllocs()
			b.ResetTimer()
			seq := uint64(1)
			for i := 0; i < b.N; i++ {
				if _, err := l.Append(bg, 1, seq, body); err != nil {
					b.Fatal(err)
				}
				seq += uint64(count)
			}
		})
	}
}
