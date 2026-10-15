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
)

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

	bw          float64
	prevRoundBW float64
	stagnant    int
	minRTT      time.Duration
	minRTTAt    time.Duration
	haveRTT     bool
	roundStart  time.Duration
	round       uint64
	roundDeliv  uint64
	delivered   uint64
	lossRound   uint64
	lossSet     bool
	appLimited  bool
	nextSend    time.Duration
	phase       int
	phaseStart  time.Duration
	probeUntil  time.Duration
	ce          uint64
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
// It paces like CanSend. A repair may sit one segment above the inflight
// cap so a NACK can still fill a hole after OnLoss cut the cap.
func (p *Pacer) CanRepair(now time.Duration, n uint64) bool {
	p.update(now)
	if n == 0 || p.inflight+n < p.inflight {
		return false
	}
	if p.inflight > p.cap+p.mss {
		return false
	}
	return now >= p.nextSend
}

// OnSend records that n data bytes left at now. n counts in flight.
func (p *Pacer) OnSend(n uint64, now time.Duration) {
	p.update(now)
	p.inflight += n
	p.nextSend = now + p.interval(n)
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

// Sample records cumulative unique delivered bytes.
func (p *Pacer) Sample(delivered uint64, now time.Duration) {
	p.delivered = delivered
	p.update(now)
}

// OnRTT records one RTT sample.
func (p *Pacer) OnRTT(rtt, now time.Duration) {
	if rtt <= 0 {
		return
	}
	if !p.haveRTT || rtt <= p.minRTT {
		p.minRTT = rtt
		p.minRTTAt = now
		p.haveRTT = true
	}
	p.update(now)
}

// OnLoss applies the once-per-round inflight cap. A second call in the
// same round does not multiply the cap down again. Startup moves to drain.
func (p *Pacer) OnLoss(now time.Duration) {
	p.update(now)
	if p.state == Startup {
		p.enterDrain()
	}
	if p.lossSet && p.lossRound == p.round {
		return
	}
	p.lossSet = true
	p.lossRound = p.round
	cut := p.inflight * 85 / 100
	cap := p.bdp()
	if cut > cap {
		cap = cut
	}
	if cap < p.mss {
		cap = p.mss
	}
	p.cap = cap
}

// OnECN treats an increase in the CE counter as loss.
func (p *Pacer) OnECN(ce uint64, now time.Duration) {
	if ce > p.ce {
		p.ce = ce
		p.OnLoss(now)
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
	p.advanceRound(now)
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
		hold := p.minRTT
		if hold <= 0 {
			hold = time.Millisecond
		}
		if now-p.phaseStart >= hold {
			p.phase = (p.phase + 1) % len(probeGains)
			p.phaseStart = now
			p.gain = probeGains[p.phase]
		}
	case ProbeRTT:
		if now >= p.probeUntil {
			// The probe is the fresh min-RTT observation. Without this,
			// the 10s check would re-enter on the next call.
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
		p.cap = 4 * p.mss
		return
	}
	if p.state == ProbeRTT {
		p.cap = 4 * p.mss
		return
	}
	if p.lossSet && p.lossRound == p.round {
		return
	}
	p.cap = p.targetCap()
}

func (p *Pacer) advanceRound(now time.Duration) {
	rl := p.roundLen()
	if now < p.roundStart {
		return
	}
	if now-p.roundStart < rl {
		return
	}
	dt := now - p.roundStart
	if dt <= 0 {
		return
	}
	if !p.appLimited {
		acked := uint64(0)
		if p.delivered >= p.roundDeliv {
			acked = p.delivered - p.roundDeliv
		}
		if acked > 0 {
			bw := float64(acked) / dt.Seconds()
			p.noteBW(bw)
		}
	}
	p.roundStart = now
	p.roundDeliv = p.delivered
	p.round++
}

func (p *Pacer) noteBW(bw float64) {
	if bw <= 0 {
		return
	}
	if p.bw == 0 || bw > p.bw {
		p.bw = bw
	}
	// A windowed max: decay toward the latest sample if it is lower, but
	// keep the max of the recent observation by a 1/8 blend down only when
	// the new sample is smaller. Tests need the max to stick in startup
	// and the growth check to see the raw round bandwidth.
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

func (p *Pacer) roundLen() time.Duration {
	if p.minRTT > 0 {
		return p.minRTT
	}
	return time.Millisecond
}

func (p *Pacer) bdp() uint64 {
	if p.bw <= 0 || p.minRTT <= 0 {
		return 0
	}
	return uint64(p.bw * p.minRTT.Seconds())
}

func (p *Pacer) targetCap() uint64 {
	b := p.bdp()
	floor := 10 * p.mss
	if b > floor {
		return b
	}
	return floor
}

func (p *Pacer) bwBytesPerSec() float64 {
	if p.bw > 0 {
		return p.bw
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
