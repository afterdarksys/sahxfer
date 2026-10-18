// Package cc is pace-bbr, a paced subset of the BBRv3 shape.
//
// It is not a byte-identical implementation of draft-ietf-ccwg-bbr.
// Reno and CUBIC are not consulted. Every DATA send, including a
// retransmission, is paced. Before a bandwidth sample the window is
// 10*MSS and the pace uses a nominal rate so a virtual clock can step
// to WakeAt.
package cc

import "time"

const (
	startupGain = 2.89
	drainGain   = 0.35
	// cwndGain is BBR's window gain. Without it the cap admits exactly
	// what the measured bandwidth covers, and startup cannot grow.
	cwndGain = 2
	// bwRounds is how many rounds of samples the bandwidth max covers.
	bwRounds = 10
	// lossBeta is the post-loss reduction for inflight_lo and bw_lo.
	lossBeta = 0.85
	// lossThresh is the round loss rate above which a round is a loss
	// round (BBRv2/v3's 2%).
	lossThresh = 0.02
	// lossRounds is how many rounds the loss rate is measured over.
	lossRounds = 4
	// startupLossSegs is the least loss, in segments, that ends startup
	// (BBRv3's full_loss_cnt): a few early drops over a small flight are
	// a high rate but not a full pipe.
	startupLossSegs = 6
	// paceSlack is the most lateness the pacer catches up.
	paceSlack = time.Millisecond
)

// FeedbackFloor is the receiver's FEEDBACK cadence floor (PROTOCOL 4.2).
// Only FEEDBACK frees inflight, so a round and the window both span at
// least this long. The engine schedules FEEDBACK from the same constant.
const FeedbackFloor = 5 * time.Millisecond

// State is the pace-bbr mode.
type State uint8

const (
	Startup State = iota
	Drain
	ProbeBW
	ProbeRTT
)

func (s State) String() string {
	switch s {
	case Startup:
		return "startup"
	case Drain:
		return "drain"
	case ProbeBW:
		return "probe_bw"
	case ProbeRTT:
		return "probe_rtt"
	default:
		return "pace"
	}
}

var probeGains = [...]float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

// Pacer gates DATA sends. Time is a virtual clock supplied by the caller.
type Pacer struct {
	mss      uint64
	state    State
	gain     float64
	cap      uint64
	inflight uint64

	bw          float64 // bw_max: max of bwWin
	bwWin       [bwRounds]float64
	bwN         int
	latest      float64
	bwLo        float64 // 0 when unset
	inflightLo  uint64  // 0 when unset
	roundSet    bool
	prevRoundBW float64
	stagnant    int
	minRTT      time.Duration
	minRTTAt    time.Duration
	haveRTT     bool
	roundStart  time.Duration
	round       uint64
	roundDeliv  uint64
	delivered   uint64
	roundLost   uint64
	lossWin     [lossRounds][2]uint64 // lost, delivered per round
	lossN       int
	appLimited  bool
	nextSend    time.Duration
	phase       int
	phaseStart  time.Duration
	probeUntil  time.Duration
	probeMin    time.Duration // least RTT sample during PROBE_RTT
	srtt        time.Duration // EWMA of OnRTT samples, gain 1/8
	startupCut  uint64        // the cut that ended STARTUP, 0 if none
	ce          uint64
	cuts        uint64
	lostTotal   uint64
}

// New returns a pacer in startup. mss is the plaintext cap, at least 1.
func New(mss uint64) *Pacer {
	if mss < 1 {
		mss = 1
	}
	return &Pacer{
		mss:   mss,
		state: Startup,
		gain:  startupGain,
		cap:   10 * mss,
	}
}

// State is the current mode.
func (p *Pacer) State() State { return p.state }

// Gain is the current pacing gain.
func (p *Pacer) Gain() float64 { return p.gain }

// Cap is the inflight byte cap.
func (p *Pacer) Cap() uint64 { return p.cap }

// LossCuts counts the loss responses that lowered inflight_lo and bw_lo.
func (p *Pacer) LossCuts() uint64 { return p.cuts }

// LossState is the controller's loss state, saved before a loss that may
// be undone (docs/design.md section 4.5, undo).
type LossState struct {
	cuts       uint64
	state      State
	stagnant   int
	inflightLo uint64
	bwLo       float64
}

// SaveLoss returns the loss state for a later UndoLoss.
func (p *Pacer) SaveLoss() LossState {
	return LossState{cuts: p.cuts, state: p.state, stagnant: p.stagnant, inflightLo: p.inflightLo, bwLo: p.bwLo}
}

// UndoLoss removes lost bytes reported after s was saved and reverts a
// loss round since then: inflight_lo, bw_lo, and a STARTUP it ended.
func (p *Pacer) UndoLoss(lost uint64, s LossState, now time.Duration) {
	if lost > p.lostTotal {
		lost = p.lostTotal
	}
	p.lostTotal -= lost
	take := func(v *uint64) {
		d := lost
		if d > *v {
			d = *v
		}
		*v -= d
		lost -= d
	}
	take(&p.roundLost)
	for i := 1; i <= lossRounds && lost > 0; i++ {
		take(&p.lossWin[((p.lossN-i)%lossRounds+lossRounds)%lossRounds][0])
	}
	if p.cuts > s.cuts {
		p.cuts = s.cuts
		p.inflightLo = s.inflightLo
		p.bwLo = s.bwLo
		// Restore STARTUP only if a reverted cut is what ended it.
		if s.state == Startup && p.startupCut > s.cuts && (p.state == Drain || p.state == ProbeBW) {
			p.startupCut = 0
			p.state = Startup
			p.gain = startupGain
			p.stagnant = s.stagnant
		}
	}
	p.update(now)
}

// Lost is the total newly lost bytes reported through OnLoss and OnECN.
func (p *Pacer) Lost() uint64 { return p.lostTotal }

// BW is the bandwidth estimate in bytes per second, min(bw_max, bw_lo).
func (p *Pacer) BW() float64 { return p.estBW() }

// Inflight is bytes sent and not yet filled.
func (p *Pacer) Inflight() uint64 { return p.inflight }

// SetAppLimited marks a period where the file, not the network, limits sends.
// An app-limited round does not change the bandwidth sample.
func (p *Pacer) SetAppLimited(v bool) { p.appLimited = v }

// CanSend reports whether n bytes of new data may leave at now.
func (p *Pacer) CanSend(now time.Duration, n uint64) bool {
	p.update(now)
	if n == 0 || p.inflight+n < p.inflight {
		return false
	}
	if p.inflight+n > p.cap {
		return false
	}
	return now >= p.nextSend
}

// CanRepair reports whether a retransmission of n bytes may leave at now.
// It paces like CanSend but is not held by the cap: bytes above a hole stay
// in flight until the hole fills, so a cap (inflight_lo in particular)
// could block the only send that frees them.
func (p *Pacer) CanRepair(now time.Duration, n uint64) bool {
	p.update(now)
	if n == 0 || p.inflight+n < p.inflight {
		return false
	}
	return now >= p.nextSend
}

// OnSend records that n data bytes left at now. n counts in flight.
func (p *Pacer) OnSend(n uint64, now time.Duration) {
	p.update(now)
	p.inflight += n
	// Schedule from the previous slot, not from now, so wake-up lateness
	// does not lower the rate. A slot more than paceSlack behind means the
	// sender was idle, not late: no credit, schedule from now.
	base := p.nextSend
	if base < now-paceSlack {
		base = now
	}
	p.nextSend = base + p.interval(n)
}

// OnFilled records that n in-flight bytes are now contiguous at the receiver.
func (p *Pacer) OnFilled(n uint64, now time.Duration) {
	if n > p.inflight {
		p.inflight = 0
	} else {
		p.inflight -= n
	}
	p.update(now)
}

// Sample records cumulative unique delivered bytes from one FEEDBACK. A
// value not above the largest seen is ignored, so a reordered FEEDBACK
// does not move the count back. The caller clamps it to bytes sent.
// FEEDBACK arrivals delimit rounds (docs/design.md section 6).
func (p *Pacer) Sample(delivered uint64, now time.Duration) {
	if delivered > p.delivered {
		p.delivered = delivered
	}
	p.advanceRound(now)
	p.update(now)
}

// OnRTT records one RTT sample.
func (p *Pacer) OnRTT(rtt, now time.Duration) {
	if rtt <= 0 {
		return
	}
	if p.srtt == 0 {
		p.srtt = rtt
	} else {
		p.srtt = (7*p.srtt + rtt) / 8
	}
	if !p.haveRTT || rtt <= p.minRTT {
		p.minRTT = rtt
		p.minRTTAt = now
		p.haveRTT = true
	}
	if p.state == ProbeRTT && (p.probeMin == 0 || rtt < p.probeMin) {
		p.probeMin = rtt
	}
	p.update(now)
}

// OnLoss adds newly lost bytes to the current round. The round's loss
// rate is judged when it ends (docs/design.md section 6).
func (p *Pacer) OnLoss(lost uint64, now time.Duration) {
	p.roundLost += lost
	p.lostTotal += lost
	p.update(now)
}

// cut is the response to a loss round: leave startup, set inflight_lo and
// bw_lo.
func (p *Pacer) cut() {
	p.cuts++
	if p.state == Startup {
		p.enterDrain()
		p.startupCut = p.cuts
	}
	lo := uint64(float64(p.inflight) * lossBeta)
	if b := p.bdp(); b > lo {
		lo = b
	}
	if lo < p.mss {
		lo = p.mss
	}
	p.inflightLo = lo
	prev := p.bwLo
	if prev == 0 {
		prev = p.bw
	}
	p.bwLo = lossBeta * prev
	if p.latest > p.bwLo {
		p.bwLo = p.latest
	}
	p.cap = p.targetCap()
}

// OnECN counts one MSS of loss per new CE mark.
func (p *Pacer) OnECN(ce uint64, now time.Duration) {
	if ce > p.ce {
		n := ce - p.ce
		p.ce = ce
		p.OnLoss(n*p.mss, now)
	}
}

// WakeAt is the next time a paced send may proceed. A caller whose
// WakeAt is not after now, and who sends nothing, must advance its own
// clock. This method does not sleep.
func (p *Pacer) WakeAt(now time.Duration) time.Duration {
	p.update(now)
	if p.nextSend > now {
		return p.nextSend
	}
	return now
}

func (p *Pacer) enterDrain() {
	p.state = Drain
	p.gain = drainGain
}

func (p *Pacer) enterProbe(now time.Duration) {
	p.state = ProbeBW
	p.phase = 0
	p.phaseStart = now
	p.gain = probeGains[0]
}

func (p *Pacer) update(now time.Duration) {
	switch p.state {
	case Drain:
		limit := p.bdp()
		if limit == 0 {
			limit = p.mss
		}
		if p.inflight <= limit {
			p.enterProbe(now)
		}
	case ProbeBW:
		if now-p.phaseStart >= p.roundLen() {
			p.phase = (p.phase + 1) % len(probeGains)
			p.phaseStart = now
			p.gain = probeGains[p.phase]
			if p.phase == 0 {
				// A completed cycle probes up again from bw_max.
				p.bwLo = 0
				p.inflightLo = 0
			}
		}
	case ProbeRTT:
		if now >= p.probeUntil {
			// RTprop becomes the least sample taken during the probe, so
			// it can rise after a route change; its age restarts either
			// way, or the 10 s check would re-enter on the next call.
			// Not above srtt: one probe of outlier samples cannot
			// raise RTprop past what the path has been showing.
			if m := p.probeMin; m > 0 {
				if p.srtt > 0 && m > p.srtt {
					m = p.srtt
				}
				if m > p.minRTT {
					p.minRTT = m
				}
			}
			p.minRTTAt = now
			p.enterProbe(now)
		}
	}
	if p.haveRTT && p.state != ProbeRTT && now-p.minRTTAt >= 10*time.Second {
		p.state = ProbeRTT
		p.gain = 1
		hold := p.minRTT
		if hold < 200*time.Millisecond {
			hold = 200 * time.Millisecond
		}
		p.probeUntil = now + hold
		p.probeMin = 0
		p.cap = 4 * p.mss
		return
	}
	if p.state == ProbeRTT {
		p.cap = 4 * p.mss
		return
	}
	p.cap = p.targetCap()
}

// advanceRound runs on a FEEDBACK arrival. The first one that delivered
// bytes starts the first round. A round ends at the first arrival at least
// roundLen after it began; bytes and time both span arrival to arrival.
func (p *Pacer) advanceRound(now time.Duration) {
	if !p.roundSet {
		if p.delivered == 0 {
			return
		}
		p.roundSet = true
		p.roundStart = now
		p.roundDeliv = p.delivered
		return
	}
	if now < p.roundStart || now-p.roundStart < p.roundLen() {
		return
	}
	dt := now - p.roundStart
	p.latest = 0
	if !p.appLimited && p.delivered > p.roundDeliv {
		bw := float64(p.delivered-p.roundDeliv) / dt.Seconds()
		p.latest = bw
		p.bwWin[p.bwN%bwRounds] = bw
		p.bwN++
		p.bw = 0
		for _, v := range p.bwWin {
			if v > p.bw {
				p.bw = v
			}
		}
		p.noteBW(bw)
	}
	p.lossWin[p.lossN%lossRounds] = [2]uint64{p.roundLost, p.delivered - p.roundDeliv}
	p.lossN++
	var lost, deliv float64
	for _, r := range p.lossWin {
		lost += float64(r[0])
		deliv += float64(r[1])
	}
	// Judge only a full window: lossRounds rounds since the first round
	// or since the previous loss round, so one noisy round right after a
	// cut is not judged alone.
	enough := p.state != Startup || lost >= float64(startupLossSegs*p.mss)
	if p.lossN >= lossRounds && enough && lost > 0 && lost > lossThresh*(deliv+lost) {
		p.cut()
		p.lossWin = [lossRounds][2]uint64{}
		p.lossN = 0
	}
	p.roundLost = 0
	p.roundStart = now
	p.roundDeliv = p.delivered
	p.round++
}

func (p *Pacer) noteBW(bw float64) {
	if bw <= 0 {
		return
	}
	// Startup growth check on the raw round bandwidth.
	if p.prevRoundBW > 0 && bw < p.prevRoundBW*1.25 {
		p.stagnant++
	} else {
		p.stagnant = 0
	}
	p.prevRoundBW = bw
	if p.state == Startup && p.stagnant >= 3 {
		p.enterDrain()
	}
}

// roundLen is L = max(minRTT, FeedbackFloor). A shorter round would divide
// one FEEDBACK's bytes by a fraction of the time they took.
func (p *Pacer) roundLen() time.Duration {
	if p.minRTT > FeedbackFloor {
		return p.minRTT
	}
	return FeedbackFloor
}

// estBW is min(bw_max, bw_lo) while bw_lo is set.
func (p *Pacer) estBW() float64 {
	if p.bwLo > 0 && p.bwLo < p.bw {
		return p.bwLo
	}
	return p.bw
}

func (p *Pacer) bdp() uint64 {
	if p.bw <= 0 || p.minRTT <= 0 {
		return 0
	}
	return uint64(p.bw * p.minRTT.Seconds())
}

// targetCap is max(2 * bw * L, 10*MSS), then at most inflight_lo: one
// RTprop plus one FEEDBACK interval of data at the estimated rate, with
// BBR's window gain (docs/design.md section 6).
func (p *Pacer) targetCap() uint64 {
	c := uint64(cwndGain * p.estBW() * p.roundLen().Seconds())
	if floor := 10 * p.mss; c < floor {
		c = floor
	}
	if p.inflightLo > 0 && p.inflightLo < c {
		c = p.inflightLo
	}
	return c
}

func (p *Pacer) bwBytesPerSec() float64 {
	if bw := p.estBW(); bw > 0 {
		return bw
	}
	// Nominal: the initial window per millisecond, so WakeAt moves.
	return float64(10*p.mss) / 0.001
}

func (p *Pacer) interval(n uint64) time.Duration {
	rate := p.gain * p.bwBytesPerSec()
	if rate < 1 {
		rate = 1
	}
	ns := float64(n) / rate * 1e9
	if ns < 1 {
		ns = 1
	}
	return time.Duration(ns)
}
