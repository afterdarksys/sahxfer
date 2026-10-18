package cc

import (
	"testing"
	"time"
)

func TestInitialWindowAndPace(t *testing.T) {
	p := New(1000)
	if p.State() != Startup || p.Gain() != startupGain {
		t.Fatalf("state %s gain %v", p.State(), p.Gain())
	}
	if p.Cap() != 10*1000 {
		t.Fatal(p.Cap())
	}
	if !p.CanSend(0, 1000) {
		t.Fatal("first send")
	}
	p.OnSend(1000, 0)
	if p.CanSend(0, 1000) {
		t.Fatal("second send was not paced")
	}
	w := p.WakeAt(0)
	if w <= 0 {
		t.Fatalf("wake %s", w)
	}
	if !p.CanSend(w, 1000) {
		t.Fatal("not ready at WakeAt")
	}
}

func TestLossCutsOncePerRound(t *testing.T) {
	p := New(100)
	p.OnSend(1000, 0)
	p.OnLoss(0)
	if p.State() != Drain || p.Gain() != drainGain {
		t.Fatalf("state %s gain %v", p.State(), p.Gain())
	}
	cap := p.Cap()
	if cap != 850 {
		t.Fatalf("cap %d", cap)
	}
	p.OnLoss(0)
	if p.Cap() != cap {
		t.Fatalf("cut twice: %d then %d", cap, p.Cap())
	}
}

func TestStartupExitsWhenBandwidthStalls(t *testing.T) {
	p := New(100)
	p.OnSend(5000, 0)
	p.OnRTT(time.Millisecond, 0)
	var del uint64
	// The first FEEDBACK starts the first round.
	for i := 1; i <= 5; i++ {
		del += 1000
		p.Sample(del, time.Duration(i)*FeedbackFloor)
	}
	if p.State() != Drain {
		t.Fatalf("state %s", p.State())
	}
}

func TestProbeBWCycle(t *testing.T) {
	p := New(100)
	p.OnRTT(time.Millisecond, 0)
	p.OnLoss(0)
	if !p.CanSend(0, 100) {
		t.Fatal("send")
	}
	if p.State() != ProbeBW || p.Gain() != 1.25 {
		t.Fatalf("enter %s %v", p.State(), p.Gain())
	}
	// A phase lasts one round, max(minRTT, FeedbackFloor).
	p.CanSend(time.Millisecond, 100)
	if p.Gain() != 1.25 {
		t.Fatalf("phase moved before a round %v", p.Gain())
	}
	p.CanSend(FeedbackFloor, 100)
	if p.Gain() != 0.75 {
		t.Fatalf("second phase %v", p.Gain())
	}
	p.CanSend(2*FeedbackFloor, 100)
	if p.Gain() != 1 {
		t.Fatalf("third phase %v", p.Gain())
	}
}

func TestProbeRTT(t *testing.T) {
	p := New(100)
	p.OnRTT(time.Millisecond, 0)
	p.CanSend(10*time.Second, 100)
	if p.State() != ProbeRTT || p.Cap() != 400 {
		t.Fatalf("state %s cap %d", p.State(), p.Cap())
	}
	p.CanSend(10*time.Second+200*time.Millisecond, 100)
	if p.State() != ProbeBW {
		t.Fatalf("left probe_rtt into %s", p.State())
	}
}

func TestECNIsLoss(t *testing.T) {
	p := New(100)
	p.OnSend(500, 0)
	p.OnECN(0, 0)
	if p.State() != Startup {
		t.Fatal(p.State())
	}
	p.OnECN(3, 0)
	if p.State() != Drain {
		t.Fatal(p.State())
	}
}

func TestAppLimitedSkipsBandwidth(t *testing.T) {
	p := New(100)
	p.OnRTT(time.Millisecond, 0)
	p.Sample(1000, FeedbackFloor)
	p.Sample(2000, 2*FeedbackFloor)
	bw := p.bw
	if bw == 0 {
		t.Fatal("no sample before app-limited")
	}
	p.SetAppLimited(true)
	p.Sample(5000, 3*FeedbackFloor)
	if p.bw != bw {
		t.Fatalf("bw changed while app-limited: %v -> %v", bw, p.bw)
	}
}

// FEEDBACK frees inflight at most every FeedbackFloor. On a path whose
// minRTT is far below that, the cap must cover the FEEDBACK interval, with
// the window gain, or the transfer is held to 10*MSS per 5 ms.
func TestCapCoversFeedbackInterval(t *testing.T) {
	p := New(1000)
	p.OnRTT(50*time.Microsecond, 0)
	// 100 KB delivered per round of FeedbackFloor: 20 MB/s.
	var del uint64
	for i := 1; i <= 3; i++ {
		del += 100_000
		p.Sample(del, time.Duration(i)*FeedbackFloor)
	}
	if p.bw < 19e6 || p.bw > 21e6 {
		t.Fatalf("bw %v, want about 20e6", p.bw)
	}
	want := uint64(cwndGain * p.bw * FeedbackFloor.Seconds())
	if p.Cap() != want || want < 190_000 {
		t.Fatalf("cap %d, want %d", p.Cap(), want)
	}

	// A path longer than the floor sizes the cap from minRTT.
	q := New(1000)
	q.OnRTT(40*time.Millisecond, 0)
	q.Sample(100_000, 40*time.Millisecond)
	q.Sample(900_000, 80*time.Millisecond)
	if want := uint64(cwndGain * q.bw * 0.040); q.Cap() != want {
		t.Fatalf("long path cap %d, want %d", q.Cap(), want)
	}
}

// A reordered FEEDBACK with a smaller delivered count must not move the
// count back, or the next round counts the same bytes twice.
func TestSampleIgnoresDecrease(t *testing.T) {
	p := New(1000)
	p.OnRTT(50*time.Microsecond, 0)
	p.Sample(10_000, FeedbackFloor)
	p.Sample(20_000, 2*FeedbackFloor)
	p.Sample(15_000, 2*FeedbackFloor+FeedbackFloor/2)
	p.Sample(30_000, 3*FeedbackFloor)
	want := 10_000 / FeedbackFloor.Seconds()
	if p.latest < want*0.99 || p.latest > want*1.01 {
		t.Fatalf("latest %v, want %v", p.latest, want)
	}
}

// FEEDBACK every 5 ms with +-200 us jitter at 10 MB/s. Timer rounds of the
// same length sometimes held two FEEDBACKs and kept a 2x sample forever.
func TestBandwidthUnderJitter(t *testing.T) {
	p := New(1000)
	p.OnRTT(50*time.Microsecond, 0)
	const rate = 10e6
	jit := []time.Duration{200, -200, 150, -50, -200, 200, 0, -150}
	for k := 1; k <= 400; k++ {
		sent := time.Duration(k) * FeedbackFloor
		at := sent + jit[k%len(jit)]*time.Microsecond
		p.Sample(uint64(rate*sent.Seconds()), at)
		if k > 20 && (p.bw > rate*1.1 || p.bw < rate*0.9) {
			t.Fatalf("feedback %d: bw %v, want about %v", k, p.bw, rate)
		}
	}
}

// bw_max is a windowed max: a high sample ages out after bwRounds rounds.
func TestBandwidthDecays(t *testing.T) {
	p := New(1000)
	p.OnRTT(50*time.Microsecond, 0)
	var del uint64
	now := time.Duration(0)
	step := func(bytes uint64) {
		del += bytes
		now += FeedbackFloor
		p.Sample(del, now)
	}
	step(1)
	step(100_000) // 20 MB/s
	for i := 0; i < bwRounds; i++ {
		step(10_000) // 2 MB/s
	}
	if want := 10_000 / FeedbackFloor.Seconds(); p.bw > want*1.01 {
		t.Fatalf("bw %v did not decay to %v", p.bw, want)
	}
}

// Loss keeps inflight_lo and bw_lo until PROBE_BW completes a cycle.
func TestLossLowHoldsUntilProbe(t *testing.T) {
	p := New(1000)
	p.OnRTT(50*time.Microsecond, 0)
	var del uint64
	now := time.Duration(0)
	step := func(bytes uint64) {
		del += bytes
		now += FeedbackFloor
		p.Sample(del, now)
	}
	step(1)
	step(100_000) // 20 MB/s, cap 2*20e6*5ms = 200 KB
	p.OnSend(100_000, now)
	p.OnLoss(now)
	if p.inflightLo != 85_000 || p.Cap() != 85_000 {
		t.Fatalf("inflight_lo %d cap %d", p.inflightLo, p.Cap())
	}
	p.OnFilled(100_000, now)
	if p.State() != ProbeBW {
		t.Fatalf("state %s", p.State())
	}
	step(100_000)
	if p.Cap() != 85_000 || p.bwLo == 0 {
		t.Fatalf("lo cleared before a probe: cap %d bw_lo %v", p.Cap(), p.bwLo)
	}
	for i := 0; i < len(probeGains)+1 && p.inflightLo != 0; i++ {
		step(100_000)
	}
	if p.inflightLo != 0 || p.bwLo != 0 || p.Cap() <= 85_000 {
		t.Fatalf("lo not cleared after a cycle: cap %d lo %d bw_lo %v", p.Cap(), p.inflightLo, p.bwLo)
	}
}

// A runner that wakes 200 us late on every send still sends at the pacing
// rate: the next slot is scheduled from the previous slot.
func TestPacingAbsorbsLateWakeups(t *testing.T) {
	p := New(1000)
	p.OnRTT(50*time.Microsecond, 0)
	p.Sample(1, 0)
	p.Sample(50_001, FeedbackFloor) // 10 MB/s
	p.OnLoss(FeedbackFloor)         // leave startup's 2.89 gain
	p.OnFilled(1<<40, FeedbackFloor)
	start := 2 * FeedbackFloor
	now := start
	sent := 0
	for now < start+100*time.Millisecond {
		if p.CanSend(now, 1000) {
			p.OnSend(1000, now)
			p.OnFilled(1000, now)
			sent++
			continue
		}
		now = p.WakeAt(now) + 200*time.Microsecond
	}
	rate := float64(sent*1000) / 0.1
	want := p.Gain() * p.estBW()
	if rate < 0.9*want {
		t.Fatalf("sent %.0f B/s, pacing rate %.0f B/s", rate, want)
	}
}
