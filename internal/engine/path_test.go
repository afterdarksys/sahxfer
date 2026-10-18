package engine

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/afterdarksys/sahxfer/internal/frame"
)

// pathCase is a one-way bottleneck for DATA with a FIFO buffer, a fixed
// delay each way, seeded random DATA loss, and an optional burst that
// swallows burstLen consecutive DATA starting at the burstAt-th.
type pathCase struct {
	bps      float64
	delay    time.Duration
	loss     float64
	seed     int64
	burstAt  int
	burstLen int
	// A route change at stepAt sets both delays to delay2.
	stepAt, delay2 time.Duration
	noStall        bool
	// An outage drops every DATA sent in [outAt, outAt+outFor).
	outAt, outFor time.Duration
}

type pathResult struct {
	took   time.Duration
	drops  int
	cuts   uint64
	lost   uint64
	retx   int
	whole  int
	goodMB float64
}

func runPath(t *testing.T, c pathCase, size int) pathResult {
	t.Helper()
	file := make([]byte, size)
	for i := range file {
		file[i] = byte(i*31 + i>>10)
	}
	pr := newPair(t, file, frame.InternetPlaintext, func(s, r *Config) {
		s.Max, r.Max = 600*time.Second, 600*time.Second
	})
	pr.dst.b = make([]byte, size)
	rng := rand.New(rand.NewSource(c.seed))
	ab := &pipe{delay: c.delay, bps: c.bps, qcap: 2*c.delay + 10*time.Millisecond, stepAt: c.stepAt, delay2: c.delay2}
	ba := &pipe{delay: c.delay, stepAt: c.stepAt, delay2: c.delay2}
	if c.stepAt > 0 && c.delay2 > c.delay {
		ab.qcap = 2*c.delay2 + 10*time.Millisecond
	}
	pr.s.noStall = c.noStall
	retx := 0
	data := 0
	drops := 0
	ab.filt = func(h frame.Header) (bool, time.Duration) {
		if h.Type != frame.TypeDATA {
			return false, 0
		}
		data++
		if h.Flags&frame.FlagRETX != 0 {
			retx++
		}
		if c.burstLen > 0 && data >= c.burstAt && data < c.burstAt+c.burstLen {
			drops++
			return true, 0
		}
		if at := time.Duration(h.SendTimeNS); c.outFor > 0 && at >= c.outAt && at < c.outAt+c.outFor {
			drops++
			return true, 0
		}
		if c.loss > 0 && rng.Float64() < c.loss {
			drops++
			return true, 0
		}
		return false, 0
	}
	now, err := runUntil(pr, ab, ba, 600*time.Second)
	if err != nil {
		t.Fatalf("%+v: at %s: %v", c, now, err)
	}
	if !bytes.Equal(pr.dst.b, file) || pr.commits != 1 {
		t.Fatalf("%+v: file mismatch or commits=%d", c, pr.commits)
	}
	return pathResult{
		took:   now,
		drops:  drops + ab.drops,
		cuts:   pr.s.pacer.LossCuts(),
		lost:   pr.s.pacer.Lost(),
		retx:   retx,
		whole:  pr.s.wholeProbes,
		goodMB: float64(size) / now.Seconds() / 1e6,
	}
}

// TestLossyPathReport logs goodput over a 5 MB/s, 20 ms each-way path at
// 0, 1 and 5 percent random DATA loss. The bounds are in the tests below.
func TestLossyPathReport(t *testing.T) {
	if testing.Short() {
		t.Skip("10 MB virtual-clock transfers")
	}
	for _, loss := range []float64{0, 0.01, 0.05} {
		r := runPath(t, pathCase{bps: 5e6, delay: 20 * time.Millisecond, loss: loss, seed: 1}, 10_000_000)
		t.Logf("loss %.0f%%: 10 MB in %v, %.2f MB/s of 5, drops %d, lost bytes reported %d (%.2f drops), loss cuts %d",
			loss*100, r.took, r.goodMB, r.drops, r.lost, float64(r.lost)/frame.InternetPlaintext, r.cuts)
	}
}

// A burst that swallows every DATA above contig mid-transfer leaves the
// receiver no hole to NACK. The tail probe re-sends the highest segment,
// which turns the swallowed range into NACKable holes. An outage that also
// eats the tail probe needs the range probe, at least 1 s later. The
// outage starts after startup: one in startup ends it at the bandwidth
// reached so far, and PROBE_BW then grows 25% per cycle, which is slow
// ramp-up, not failed recovery.
func TestBurstLossMidTransfer(t *testing.T) {
	if testing.Short() {
		t.Skip("virtual-clock transfers")
	}
	for _, delay := range []time.Duration{2 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond} {
		for _, c := range []pathCase{
			{bps: 5e6, delay: delay, burstAt: 1000, burstLen: 60},
			{bps: 5e6, delay: delay, outAt: time.Second, outFor: 300 * time.Millisecond},
		} {
			r := runPath(t, c, 6_000_000)
			t.Logf("delay %v burst %d outage %v: %v, %.2f MB/s, %d range probes, %d lost bytes", delay, c.burstLen, c.outFor, r.took, r.goodMB, r.whole, r.lost)
			if r.took > 8*time.Second {
				t.Fatalf("delay %v burst %d outage %v took %v", delay, c.burstLen, c.outFor, r.took)
			}
		}
	}
}

// Random 1% loss is under the 2% loss-round threshold: goodput stays at
// least 80% of the lossless run on the same 5 MB/s, 20 ms each-way path
// (measured 3.34 vs 3.80 MB/s; it was 0.69 when every lossy round cut).
func TestGoodputUnderRandomLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("10 MB virtual-clock transfers")
	}
	c := pathCase{bps: 5e6, delay: 20 * time.Millisecond, seed: 1}
	clean := runPath(t, c, 10_000_000)
	c.loss = 0.01
	lossy := runPath(t, c, 10_000_000)
	if lossy.goodMB < 0.8*clean.goodMB {
		t.Fatalf("1%% loss: %.2f MB/s, lossless %.2f MB/s", lossy.goodMB, clean.goodMB)
	}
}

// Each dropped DATA reaches the controller once: the receiver repeats its
// hole list every RTT, and a re-NACK of a hole under repair is not new
// loss. Tail drops recovered by the stall probe are never NACKed, so the
// count may fall a little short of the drops, never above them.
func TestLossCountedOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("10 MB virtual-clock transfers")
	}
	for _, loss := range []float64{0.01, 0.05} {
		r := runPath(t, pathCase{bps: 5e6, delay: 20 * time.Millisecond, loss: loss, seed: 1}, 10_000_000)
		most := uint64(r.drops) * frame.InternetPlaintext
		if r.lost > most || r.lost < most*8/10 {
			t.Fatalf("loss %v: %d bytes reported lost for %d drops (%d bytes)", loss, r.lost, r.drops, most)
		}
	}
}

// A healthy transfer reports progress only by FEEDBACK, every 5 ms. The
// stall probe must not fire between two FEEDBACKs on a short path and
// resend the window.
func TestNoSpuriousStallProbe(t *testing.T) {
	for _, delay := range []time.Duration{100 * time.Microsecond, time.Millisecond, 20 * time.Millisecond} {
		file := make([]byte, 2_000_000)
		pr := newPair(t, file, frame.InternetPlaintext, nil)
		pr.dst.b = make([]byte, len(file))
		ab := &pipe{delay: delay, bps: 20e6, qcap: 2*delay + 10*time.Millisecond}
		retx := 0
		ab.filt = func(h frame.Header) (bool, time.Duration) {
			if h.Type == frame.TypeDATA && h.Flags&frame.FlagRETX != 0 {
				retx++
			}
			return false, 0
		}
		if now, err := runUntil(pr, ab, &pipe{delay: delay}, 10*time.Second); err != nil {
			t.Fatalf("delay %v at %s: %v", delay, now, err)
		}
		if retx != 0 || ab.drops != 0 {
			t.Fatalf("delay %v: %d retransmissions, %d drops on a clean path", delay, retx, ab.drops)
		}
	}
}

// A route change raises the delay mid-transfer. FEEDBACK then stops for
// longer than any wait computed on the old RTT; the stall probe must not
// read that as loss and resend the window. No range probe may fire, and
// completion stays within 1.5x of the run with the probe off. The factor
// is not 1.0 because the one tail-probe segment shifts when startup exits
// while RTprop is still the old one: measured 1.01x, 0.97x and 1.39x, and
// a single DATA delayed 3 ms moves the probe-off run by -11% to +2%.
func TestDelayStepNoSpuriousProbe(t *testing.T) {
	if testing.Short() {
		t.Skip("10 MB virtual-clock transfers")
	}
	for _, d := range [][2]time.Duration{
		{10 * time.Millisecond, 100 * time.Millisecond},
		{10 * time.Millisecond, 200 * time.Millisecond},
		{50 * time.Millisecond, 250 * time.Millisecond},
	} {
		c := pathCase{bps: 5e6, delay: d[0], stepAt: time.Second, delay2: d[1]}
		c.noStall = true
		base := runPath(t, c, 10_000_000)
		c.noStall = false
		got := runPath(t, c, 10_000_000)
		t.Logf("%v->%v: %v (probe off %v), %d retx, %d whole-range probes", d[0], d[1], got.took, base.took, got.retx, got.whole)
		if got.whole != 0 || got.took > base.took*3/2 {
			t.Fatalf("%v->%v: %v vs probe off %v, %d whole-range probes", d[0], d[1], got.took, base.took, got.whole)
		}
	}
}
