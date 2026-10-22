package cc

import (
	"testing"
	"time"
)

func TestDelayedFeedbackAllowsStartupGrowth(t *testing.T) {
	p := New(1152)
	p.OnRTT(time.Millisecond, 0)
	p.Sample(10*1152, 20*time.Millisecond)
	p.Sample(20*1152, 40*time.Millisecond)
	if p.Cap() < 20*1152 {
		t.Fatalf("window trapped by delayed feedback: %d", p.Cap())
	}
	// Replays and no-progress reports cannot refresh aggregation credit.
	n := p.feedbackN
	p.Sample(20*1152, time.Second)
	p.Sample(1, 2*time.Second)
	if p.feedbackN != n {
		t.Fatal("stale delivery changed aggregation")
	}
	p.Sample(30*1152, 3*time.Second)
	for _, gap := range p.feedbackGaps {
		if gap > 50*time.Millisecond {
			t.Fatal("unbounded outage allowance")
		}
	}
	// Steady fast feedback expires the old aggregation window.
	for i := 1; i <= bwRounds; i++ {
		p.Sample(uint64(30+i)*1152, 3*time.Second+time.Duration(i)*time.Millisecond)
	}
	for _, gap := range p.feedbackGaps {
		if gap > time.Millisecond {
			t.Fatal("aggregation never aged out")
		}
	}
}

func TestFirstSendHasNoAccumulatedCredit(t *testing.T) {
	for _, now := range []time.Duration{0, time.Millisecond, 2 * time.Millisecond, time.Hour} {
		p := New(1152)
		if !p.CanSend(now, 1152) {
			t.Fatal("first send blocked")
		}
		p.OnSend(1152, now)
		if p.CanSend(now, 1152) {
			t.Fatalf("first send at %v inherited credit", now)
		}
	}
}

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

// steps drives FEEDBACK arrivals one FeedbackFloor apart.
type steps struct {
	p   *Pacer
	now time.Duration
	del uint64
}

func (s *steps) step(bytes uint64) {
	s.del += bytes
	s.now += FeedbackFloor
	s.p.Sample(s.del, s.now)
}

// newSteps starts the first round, then ends lossRounds-1 growing rounds
// (2.5, 5, 10 MB/s) so startup holds and the next round fills the loss
// window.
func newSteps(mss uint64) *steps {
	p := New(mss)
	p.OnRTT(50*time.Microsecond, 0)
	s := &steps{p: p}
	s.step(1) // the first FEEDBACK starts the first round
	for _, b := range []uint64{12_500, 25_000, 50_000} {
		s.step(b)
	}
	return s
}

// A loss round is judged when the round ends: several losses in one round
// cut once. Startup needs startupLossSegs lost segments as well as the rate.
func TestLossRound(t *testing.T) {
	s := newSteps(1000)
	s.p.OnSend(100_000, s.now)
	// 5 segments over a full window of 187.5 KB is 2.6%: above the rate
	// threshold, under startupLossSegs, so startup holds.
	s.p.OnLoss(5000, s.now)
	s.step(100_000)
	if s.p.State() != Startup || s.p.LossCuts() != 0 {
		t.Fatalf("5 segments at 2.6%% ended startup: %s cuts %d", s.p.State(), s.p.LossCuts())
	}
	for i := 0; i < 4; i++ {
		s.p.OnLoss(2000, s.now)
	}
	if s.p.LossCuts() != 0 {
		t.Fatal("cut before the round ended")
	}
	s.step(100_000)
	if s.p.State() != Drain || s.p.Gain() != drainGain || s.p.LossCuts() != 1 {
		t.Fatalf("state %s gain %v cuts %d", s.p.State(), s.p.Gain(), s.p.LossCuts())
	}
	if s.p.Cap() != 85_000 {
		t.Fatalf("cap %d, want 0.85 * inflight", s.p.Cap())
	}
	if s.p.Lost() != 13_000 {
		t.Fatalf("lost %d", s.p.Lost())
	}
}

// Past startup, 1% loss is below the 2% threshold measured over
// lossRounds rounds and never cuts; 3% does.
func TestLossThreshold(t *testing.T) {
	s := newSteps(1000)
	s.p.enterDrain()
	for i := 0; i < 40; i++ {
		s.p.OnLoss(1000, s.now)
		s.step(100_000)
	}
	if s.p.LossCuts() != 0 {
		t.Fatalf("1%% loss cut %d times", s.p.LossCuts())
	}
	// Measured over lossRounds rounds, so a steady 3% cuts within that
	// many rounds, and once.
	for i := 0; i < lossRounds; i++ {
		s.p.OnLoss(3000, s.now)
		s.step(100_000)
	}
	if s.p.LossCuts() != 1 {
		t.Fatalf("3%% loss cut %d times", s.p.LossCuts())
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
	p.enterDrain()
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

// Each new CE mark counts one MSS of loss in the round.
func TestECNIsLoss(t *testing.T) {
	s := newSteps(1000)
	s.p.OnSend(50_000, s.now)
	s.p.OnECN(0, s.now)
	if s.p.Lost() != 0 {
		t.Fatal(s.p.Lost())
	}
	s.p.OnECN(7, s.now)
	s.p.OnECN(7, s.now)
	if s.p.Lost() != 7000 {
		t.Fatalf("lost %d", s.p.Lost())
	}
	s.step(50_000)
	if s.p.State() != Drain {
		t.Fatal(s.p.State())
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

// bw_max is a windowed max: a high sample holds for bwRounds-1 later
// sampled rounds and ages out on the next.
func TestBandwidthDecays(t *testing.T) {
	s := newSteps(1000)
	s.step(100_000) // 20 MB/s
	high := 100_000 / FeedbackFloor.Seconds()
	low := 10_000 / FeedbackFloor.Seconds()
	for i := 0; i < bwRounds-1; i++ {
		s.step(10_000) // 2 MB/s
	}
	if s.p.bw < high*0.99 {
		t.Fatalf("bw %v aged out before %d rounds", s.p.bw, bwRounds)
	}
	s.step(10_000)
	if s.p.bw > low*1.01 {
		t.Fatalf("bw %v did not decay to %v", s.p.bw, low)
	}
}

// lossState cuts once: 100 KB in flight, 10 segments lost in a round.
func lossState(t *testing.T) *steps {
	t.Helper()
	s := newSteps(1000)
	s.step(100_000) // 20 MB/s, cap 2*20e6*5ms = 200 KB
	s.p.OnSend(100_000, s.now)
	s.p.OnLoss(10_000, s.now)
	s.step(100_000)
	if s.p.LossCuts() != 1 || s.p.inflightLo != 85_000 || s.p.Cap() != 85_000 {
		t.Fatalf("cuts %d inflight_lo %d cap %d", s.p.LossCuts(), s.p.inflightLo, s.p.Cap())
	}
	s.p.OnFilled(100_000, s.now)
	if s.p.State() != ProbeBW || s.p.phase != 0 {
		t.Fatalf("state %s phase %d", s.p.State(), s.p.phase)
	}
	return s
}

// Loss keeps inflight_lo and bw_lo through phases 1..7 and clears them
// exactly when the cycle wraps to the 1.25 phase.
func TestLossLowHoldsUntilProbe(t *testing.T) {
	s := lossState(t)
	for i := 1; i < len(probeGains); i++ {
		s.step(100_000)
		if s.p.phase != i || s.p.inflightLo != 85_000 || s.p.bwLo == 0 || s.p.Cap() != 85_000 {
			t.Fatalf("step %d: phase %d inflight_lo %d bw_lo %v cap %d", i, s.p.phase, s.p.inflightLo, s.p.bwLo, s.p.Cap())
		}
	}
	s.step(100_000)
	if s.p.phase != 0 || s.p.inflightLo != 0 || s.p.bwLo != 0 || s.p.Cap() != 200_000 {
		t.Fatalf("at the wrap: phase %d inflight_lo %d bw_lo %v cap %d", s.p.phase, s.p.inflightLo, s.p.bwLo, s.p.Cap())
	}
}

// PROBE_RTT -> PROBE_BW enters phase 0 without completing a cycle, so the
// loss state stays.
func TestLossLowSurvivesProbeRTT(t *testing.T) {
	s := lossState(t)
	at := 10*time.Second + FeedbackFloor
	s.p.CanSend(at, 1000)
	if s.p.State() != ProbeRTT {
		t.Fatalf("state %s", s.p.State())
	}
	s.p.CanSend(at+200*time.Millisecond, 1000)
	if s.p.State() != ProbeBW || s.p.phase != 0 {
		t.Fatalf("state %s phase %d", s.p.State(), s.p.phase)
	}
	if s.p.inflightLo != 85_000 || s.p.bwLo == 0 || s.p.Cap() != 85_000 {
		t.Fatalf("PROBE_RTT exit cleared the loss state: inflight_lo %d bw_lo %v cap %d", s.p.inflightLo, s.p.bwLo, s.p.Cap())
	}
}

// pacedAt10MB is a pacer in PROBE_BW at 10 MB/s with nothing in flight.
func pacedAt10MB() (*Pacer, time.Duration) {
	s := newSteps(1000)
	s.step(50_000) // 10 MB/s
	s.p.enterDrain()
	s.p.CanSend(s.now, 1000) // drain exits into PROBE_BW
	return s.p, s.now
}

// A runner that wakes 200 us late on every send still sends at the pacing
// rate: the next slot is scheduled from the previous slot.
func TestPacingAbsorbsLateWakeups(t *testing.T) {
	for _, late := range []time.Duration{200 * time.Microsecond, 1100 * time.Microsecond} {
		p, start := pacedAt10MB()
		now := start
		sent := 0
		for now < start+100*time.Millisecond {
			if p.CanSend(now, 1000) {
				p.OnSend(1000, now)
				p.OnFilled(1000, now)
				sent++
				continue
			}
			now = p.WakeAt(now) + late
		}
		rate := float64(sent*1000) / 0.1
		if want := 10e6; rate < 0.9*want {
			t.Fatalf("sent %.0f B/s, pacing rate about %.0f B/s", rate, want)
		}
	}
}

// burstAt sends one segment at t0, then counts the segments that may leave
// at once when the runner wakes late past the next slot.
func burstAt(t *testing.T, late time.Duration) (int, time.Duration) {
	t.Helper()
	p, t0 := pacedAt10MB()
	p.OnSend(1000, t0)
	p.OnFilled(1000, t0)
	now := p.WakeAt(t0) + late
	iv := p.interval(1000)
	n := 0
	for p.CanSend(now, 1000) {
		p.OnSend(1000, now)
		p.OnFilled(1000, now)
		n++
		if n > 1000 {
			t.Fatal("unbounded burst")
		}
	}
	return n, iv
}

// 1.9 ms late: catch up at most about 2 ms of data plus one segment.
func TestPacingLateBurstLimit(t *testing.T) {
	n, iv := burstAt(t, 1900*time.Microsecond)
	most := int(paceSlack/iv) + 1
	least := int(1900 * time.Microsecond / iv)
	if n > most || n < least {
		t.Fatalf("1.9 ms late sent %d segments, want %d..%d (slot %v)", n, least, most, iv)
	}
}

// More than 2 ms behind means idle: one segment, then a paced gap.
func TestPacingNoCreditAfterIdle(t *testing.T) {
	if n, _ := burstAt(t, 2500*time.Microsecond); n != 1 {
		t.Fatalf("2.5 ms late sent %d segments, want 1", n)
	}
	p, t0 := pacedAt10MB()
	p.OnSend(1000, t0)
	p.OnFilled(1000, t0)
	now := t0 + 5*time.Millisecond
	if !p.CanSend(now, 1000) {
		t.Fatal("no send after idle")
	}
	p.OnSend(1000, now)
	p.OnFilled(1000, now)
	if p.CanSend(now, 1000) {
		t.Fatal("idle gave credit: a second segment at the same instant")
	}
	if w := p.WakeAt(now); w <= now {
		t.Fatalf("no gap after the first segment: wake %v now %v", w, now)
	}
}

// RTprop can rise: PROBE_RTT ends with the least sample taken during it,
// capped at the controller's srtt. A route change from 100 ms to 500 ms
// otherwise keeps 100 ms forever.
func TestRTpropRisesAfterProbeRTT(t *testing.T) {
	p := New(1000)
	p.OnRTT(100*time.Millisecond, 0)
	// After the route change every sample is 500 ms; srtt follows.
	for at := time.Second; at < 10*time.Second; at += 100 * time.Millisecond {
		p.OnRTT(500*time.Millisecond, at)
	}
	p.CanSend(10*time.Second, 1000)
	if p.State() != ProbeRTT {
		t.Fatalf("state %s", p.State())
	}
	p.OnRTT(520*time.Millisecond, 10*time.Second+50*time.Millisecond)
	p.OnRTT(500*time.Millisecond, 10*time.Second+100*time.Millisecond)
	p.CanSend(10*time.Second+200*time.Millisecond, 1000)
	if p.State() != ProbeBW || p.minRTT < 499*time.Millisecond || p.minRTT > 500*time.Millisecond {
		t.Fatalf("state %s RTprop %v, want 500ms", p.State(), p.minRTT)
	}
	// No sample during the probe: RTprop stays, its age restarts.
	before := p.minRTT
	p.CanSend(20*time.Second+200*time.Millisecond, 1000)
	p.CanSend(20*time.Second+800*time.Millisecond, 1000)
	if p.State() != ProbeBW || p.minRTT != before {
		t.Fatalf("state %s RTprop %v", p.State(), p.minRTT)
	}
}

// One probe whose samples are all outliers cannot raise RTprop past srtt.
func TestRTpropRiseCappedAtSRTT(t *testing.T) {
	p := New(1000)
	for at := time.Duration(0); at < 10*time.Second; at += 100 * time.Millisecond {
		p.OnRTT(100*time.Millisecond, at)
	}
	p.CanSend(20*time.Second, 1000)
	if p.State() != ProbeRTT {
		t.Fatalf("state %s", p.State())
	}
	p.OnRTT(900*time.Millisecond, 20*time.Second+50*time.Millisecond)
	p.CanSend(20*time.Second+200*time.Millisecond, 1000)
	if p.minRTT > p.srtt || p.minRTT >= 900*time.Millisecond {
		t.Fatalf("RTprop %v, srtt %v: outlier probe raised it past srtt", p.minRTT, p.srtt)
	}
}

// UndoLoss reverts a loss round: the loss, the cut, inflight_lo, bw_lo,
// and the STARTUP that cut ended.
func TestUndoLossRestores(t *testing.T) {
	s := newSteps(1000)
	snap := s.p.SaveLoss()
	s.p.OnSend(100_000, s.now)
	s.p.OnLoss(10_000, s.now)
	s.step(100_000)
	if s.p.State() != Drain || s.p.LossCuts() != 1 || s.p.inflightLo == 0 || s.p.bwLo == 0 {
		t.Fatalf("no cut to undo: %s cuts %d", s.p.State(), s.p.LossCuts())
	}
	s.p.UndoLoss(10_000, snap, s.now)
	if s.p.State() != Startup || s.p.Gain() != startupGain {
		t.Fatalf("STARTUP not restored: %s gain %v", s.p.State(), s.p.Gain())
	}
	if s.p.inflightLo != 0 || s.p.bwLo != 0 || s.p.LossCuts() != 0 || s.p.Lost() != 0 {
		t.Fatalf("inflight_lo %d bw_lo %v cuts %d lost %d", s.p.inflightLo, s.p.bwLo, s.p.LossCuts(), s.p.Lost())
	}
}

// STARTUP that ended without a cut (bandwidth stalled) after the snapshot
// is not restored by undoing a later cut.
func TestUndoLossKeepsStallExit(t *testing.T) {
	s := newSteps(1000)
	snap := s.p.SaveLoss() // taken in STARTUP
	for i := 0; i < 4; i++ {
		s.step(50_000)
	}
	if s.p.State() == Startup || s.p.LossCuts() != 0 {
		t.Fatalf("startup did not stall out: %s cuts %d", s.p.State(), s.p.LossCuts())
	}
	s.p.OnSend(50_000, s.now)
	s.p.OnLoss(10_000, s.now)
	s.step(50_000)
	if s.p.LossCuts() != 1 {
		t.Fatalf("cuts %d", s.p.LossCuts())
	}
	s.p.UndoLoss(10_000, snap, s.now)
	if s.p.State() == Startup || s.p.LossCuts() != 0 || s.p.inflightLo != 0 {
		t.Fatalf("state %s cuts %d inflight_lo %d", s.p.State(), s.p.LossCuts(), s.p.inflightLo)
	}
}
