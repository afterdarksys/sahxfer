package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestLocalProducerConsumerRecovery(t *testing.T) {
	var out bytes.Buffer
	if err := run(&out, 129, 1024, 64); err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["persisted"] != float64(129) || result["processed"] != float64(129) || result["duplicate_batches"] != float64(1) || result["replayed_records"] != float64(193) {
		t.Fatal(result)
	}
	if bytes.Contains(out.Bytes(), payload(1, 1024)) {
		t.Fatal("payload in output")
	}
}

func TestWorkloadBounds(t *testing.T) {
	for _, v := range [][3]int{{0, 1024, 64}, {1, 0, 1}, {1, 1024, 0}, {1, 1 << 20, 1024}, {65536, 1 << 20, 1}} {
		var out bytes.Buffer
		if err := run(&out, v[0], v[1], v[2]); err == nil || out.Len() != 0 {
			t.Fatal("invalid workload accepted")
		}
	}
}
