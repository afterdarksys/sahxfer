// Package engine is the in-process sahxfer sender and receiver.
//
// Threats: a replayed DATA does not increase delivered bytes; a tag,
// magic, version, or length failure is not written; offset wrap or a
// span past the grant aborts with the temp file cleaned up; the 32nd
// AEAD or route-token failure kills the grant; a DONE hash that does not
// match the grant does not report success. It does not defend a source
// that changes under the sender, or a destination that reports a write
// it did not perform.
//
// The clock is virtual. Pump and Recv do not sleep and do not read time.Now.
package engine

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"sort"
	"time"

	"github.com/afterdarksys/sahxfer/internal/cc"
	"github.com/afterdarksys/sahxfer/internal/frame"
	"github.com/afterdarksys/sahxfer/internal/hole"
	"github.com/afterdarksys/sahxfer/internal/seal"
)

const (
	TransportUDP          = "udp"
	TransportQUICDatagram = "quic-datagram"
	TransportQUICBridge   = "quic-bridge"
	TransportQUICStream   = "quic-stream"
)

const (
	stPinging state = iota
	stSending
	stFlushing
	stDone
	stAbort
)

type state uint8

// AbortError is a terminal grant failure. Error() is the reason name.
type AbortError struct {
	Reason uint64
}

func (e *AbortError) Error() string {
	if e == nil {
		return "abort"
	}
	return frame.ReasonName(e.Reason)
}

// Config is one side of one grant. Key and Token are copied into the
// session; this value is not retained with those fields set.
type Config struct {
	TransferID uint64
	Size       uint64
	MSS        uint64
	Key        []byte
	Token      []byte
	LocalDir   byte
	PeerDir    byte
	Sender     bool
	Transport  string
	// Pacing is forced on for udp. quic-datagram and quic-bridge reject true.
	Pacing      bool
	Profile     string
	Idle        time.Duration
	Max         time.Duration
	FirstPacket time.Duration
	ByteCap     uint64
	ExpectHash  [32]byte
	HaveHash    bool
}

// Hooks run around commit. Commit is fsync plus rename. Cleanup deletes
// the temp file. A nil Commit succeeds. Cleanup is not called after a
// successful commit.
type Hooks struct {
	Commit  func() error
	Cleanup func()
}

// File is the receiver's temp file. The hash reads back what was written.
type File interface {
	io.ReaderAt
	io.WriterAt
}

// Peer is one side of a transfer.
type Peer struct {
	cfg    Config
	hooks  Hooks
	sess   *seal.Session
	holes  *hole.Map
	pacer  *cc.Pacer
	src    io.ReaderAt
	dest   File
	hash   hash.Hash
	state  state
	reason uint64
	fail   error

	started      bool
	start        time.Duration
	lastRx       time.Duration
	lastProgress time.Duration
	sawPeer      bool
	// firstRx is when the first authentic packet arrived. A PING sealed
	// before it may have waited in a pre-pin queue or a relay hold, so
	// its PONG is not a path RTT sample.
	firstRx time.Duration

	seq        uint64
	srtt       time.Duration
	rttvar     time.Duration
	haveRTT    bool
	out        [][]byte
	unpaced    bool
	committed  bool
	gotClose   bool
	cleaned    bool
	finSeen    bool
	ponged     bool
	closeAck   bool
	pings      int
	lastPing   time.Duration
	extraPing  bool
	probe      uint64
	rxPingSent bool
	rePinged   bool

	nextNew  uint64
	contig   uint64
	retx     []frame.Span
	inflight []sentSeg
	// progAt is the last advance of contig or FEEDBACK delivered bytes,
	// or the last stall probe. probes counts stall probes since progress.
	progAt    time.Duration
	probes    uint
	fbDeliv   uint64
	recheckAt time.Duration
	// noStall turns the stall probe off; tests use it as a baseline.
	noStall bool
	// wholeProbes counts stall probes that resent a range (not a TLP).
	wholeProbes int
	lastFIN     time.Duration
	finQueued   bool

	lastNACK    time.Duration
	nackSig     uint64
	nackSent    bool
	lastFB      time.Duration
	fbSent      bool
	dataSinceFB int
	fbLost      uint64
	highSeq     uint64
	highSent    uint64
	lastEcho    uint64
	lastDONE    time.Duration
	doneSent    bool
	hashedTo    uint64
	doneSum     []byte
}

type sentSeg struct {
	start, end uint64
	n          uint64
	at         time.Duration
	retx       bool
}

// New checks the grant shape and opens the AEAD session.
func New(cfg Config) (*Peer, error) {
	if cfg.Size >= 1<<63 {
		return nil, errors.New("sahxfer: size")
	}
	if cfg.LocalDir > 1 || cfg.PeerDir > 1 {
		return nil, errors.New("sahxfer: direction")
	}
	switch cfg.Transport {
	case "", TransportUDP:
		cfg.Transport = TransportUDP
		cfg.Pacing = true
	case TransportQUICDatagram, TransportQUICBridge:
		if cfg.Pacing {
			return nil, errors.New("sahxfer: pacing")
		}
	default:
		return nil, errors.New("sahxfer: transport")
	}
	if cfg.MSS == 0 {
		if cfg.Profile == "dc" {
			cfg.MSS = frame.DCPlaintext
		} else {
			cfg.MSS = frame.InternetPlaintext
		}
	}
	if cfg.MSS < 1 || cfg.MSS > frame.MaxPlaintext {
		return nil, errors.New("sahxfer: mss")
	}
	if cfg.Idle <= 0 {
		cfg.Idle = 30 * time.Second
	}
	if cfg.Max <= 0 {
		cfg.Max = 3600 * time.Second
	}
	if cfg.FirstPacket <= 0 {
		cfg.FirstPacket = 60 * time.Second
	}
	if cfg.ByteCap == 0 {
		cfg.ByteCap = cfg.Size
	}
	sess, err := seal.New(cfg.Key, cfg.Token)
	if err != nil {
		return nil, err
	}
	hm, err := hole.New(cfg.Size)
	if err != nil {
		sess.Wipe()
		return nil, err
	}
	cfg.Key = nil
	cfg.Token = nil
	p := &Peer{
		cfg:   cfg,
		sess:  sess,
		holes: hm,
		hash:  sha256.New(),
		state: stPinging,
	}
	if cfg.Pacing {
		p.pacer = cc.New(cfg.MSS)
	}
	return p, nil
}

// SetHooks installs commit and cleanup. Either may be nil.
func (p *Peer) SetHooks(h Hooks) { p.hooks = h }

// AttachSource is the sender's file. When the grant carries a hash, it is
// checked before any DATA is sent.
func (p *Peer) AttachSource(r io.ReaderAt) error {
	p.src = r
	if !p.cfg.Sender || p.cfg.Size == 0 || !p.cfg.HaveHash {
		return nil
	}
	h := sha256.New()
	buf := make([]byte, 32<<10)
	var off uint64
	for off < p.cfg.Size {
		n := uint64(len(buf))
		if p.cfg.Size-off < n {
			n = p.cfg.Size - off
		}
		nr, err := r.ReadAt(buf[:n], int64(off))
		if nr > 0 {
			if _, werr := h.Write(buf[:nr]); werr != nil {
				return werr
			}
			off += uint64(nr)
		}
		if err != nil {
			return err
		}
		if nr == 0 {
			return io.ErrUnexpectedEOF
		}
	}
	if !sameSum(h.Sum(nil), p.cfg.ExpectHash[:]) {
		return errors.New("sahxfer: hash_mismatch")
	}
	return nil
}

// AttachDest is the receiver's temp file.
func (p *Peer) AttachDest(f File) { p.dest = f }

// Pump runs one virtual instant. It does not block.
func (p *Peer) Pump(now time.Duration) {
	p.unpaced = false
	p.tick(now)
	if p.state == stAbort {
		return
	}
	p.timeouts(now)
	if p.state == stAbort {
		return
	}
	if p.cfg.Sender {
		p.maybeRePing(now)
		p.maybePing(now)
		p.maybeStall(now)
		if p.state == stFlushing || p.state == stDone {
			p.maybeFIN(now)
		}
		if p.state == stSending || p.state == stFlushing {
			p.sendData(now)
		}
		return
	}
	if !p.rxPingSent {
		p.emitPing(now)
		p.rxPingSent = true
	}
	p.maybeRePing(now)
	p.maybeNACK(now)
	p.maybeFeedback(now)
	p.maybeVerify(now)
	if p.committed && !p.gotClose {
		p.maybeDONE(now)
	}
}

// Recv authenticates one datagram and applies it.
func (p *Peer) Recv(now time.Duration, dgram []byte) {
	p.tick(now)
	if p.state == stAbort {
		return
	}
	h, pt, err := p.sess.Open(dgram, p.cfg.PeerDir)
	if errors.Is(err, seal.ErrBudget) {
		p.abort(now, frame.ReasonAuth)
		return
	}
	if err != nil {
		return
	}
	if h.TransferID != p.cfg.TransferID {
		return
	}
	if !frame.KnownType(h.Type) || !frame.FlagsOK(h.Type, h.Flags) {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	if !p.sawPeer {
		p.firstRx = now
	}
	p.sawPeer = true
	p.lastRx = now
	p.lastProgress = now
	switch h.Type {
	case frame.TypeDATA:
		p.onData(now, h, pt)
	case frame.TypeNACK:
		p.onNACK(now, h, pt)
	case frame.TypeFEEDBACK:
		p.onFeedback(now, h, pt)
	case frame.TypeFIN:
		p.onFIN(now, h, pt)
	case frame.TypeDONE:
		p.onDONE(now, h, pt)
	case frame.TypeABORT:
		p.onAbort(h, pt)
	case frame.TypePING:
		p.onPing(now, h, pt)
	case frame.TypePONG:
		p.onPong(now, h, pt)
	default:
		p.abort(now, frame.ReasonProtocol)
	}
}

// Take returns datagrams produced since the previous take.
func (p *Peer) Take() [][]byte {
	out := p.out
	p.out = nil
	return out
}

// WakeAt is the next time Pump should run. now means "ready".
// A caller that produces nothing must advance its own clock.
func (p *Peer) WakeAt(now time.Duration) time.Duration {
	if p.state == stAbort || (p.OK()) {
		return now + p.cfg.Max
	}
	next := now + p.cfg.Max
	consider := func(t time.Duration) {
		if t > now && t < next {
			next = t
		}
	}
	if p.cfg.Sender && p.wantData() {
		if p.pacer == nil {
			return now
		}
		n := p.nextLen()
		if p.pacer.CanSend(now, n) || (len(p.retx) > 0 && p.pacer.CanRepair(now, n)) {
			return now
		}
		if w := p.pacer.WakeAt(now); w > now {
			consider(w)
		}
	}
	if !p.sawPeer {
		consider(p.start + p.cfg.FirstPacket)
	} else {
		consider(p.lastProgress + p.cfg.Idle)
	}
	consider(p.start + p.cfg.Max)
	if p.cfg.Sender && !p.ponged {
		if p.pings > 0 && p.pings < 3 {
			consider(p.lastPing + 10*time.Millisecond)
		}
		if !p.extraPing {
			consider(p.start + time.Second)
		}
	}
	if p.cfg.Sender && (p.state == stFlushing || p.state == stDone) {
		if !p.finQueued {
			// The first FIN is due as soon as FLUSHING starts.
			return now
		}
		consider(p.lastFIN + p.rtt())
	}
	if p.cfg.Sender && p.stalling() && !p.noStall {
		consider(p.stallStart() + p.stallWait())
		consider(p.recheckAt)
	}
	if !p.cfg.Sender {
		if !p.fbSent {
			consider(p.start + cc.FeedbackFloor)
		} else {
			consider(p.lastFB + p.fbEvery())
		}
		if p.nackSent {
			consider(p.lastNACK + p.rtt())
		}
		if p.committed && !p.gotClose {
			consider(p.lastDONE + p.rtt())
		}
	}
	return next
}

// OK reports a finished transfer this side accepts.
// The sender has checked DONE. The receiver has committed and seen CLOSE_ACK.
func (p *Peer) OK() bool {
	if p.cfg.Sender {
		return p.state == stDone
	}
	return p.committed && p.gotClose
}

// Err is the terminal failure, or nil.
func (p *Peer) Err() error { return p.fail }

// Reason is the ABORT code, or 0.
func (p *Peer) Reason() uint64 { return p.reason }

// Close wipes the session key and route token. The cipher library may
// retain its own key copy until it is garbage-collected.
func (p *Peer) Close() {
	if p == nil || p.sess == nil {
		return
	}
	p.sess.Wipe()
	p.sess = nil
}

// Delivered is unique file bytes accepted (receiver) or acknowledged (sender).
func (p *Peer) Delivered() uint64 {
	if p.cfg.Sender {
		return p.contig
	}
	if p.holes == nil {
		return 0
	}
	return p.holes.Delivered()
}

func (p *Peer) tick(now time.Duration) {
	if p.started {
		return
	}
	p.started = true
	p.start = now
	p.lastProgress = now
}

func (p *Peer) timeouts(now time.Duration) {
	if !p.started {
		return
	}
	if now-p.start >= p.cfg.Max {
		p.abort(now, frame.ReasonExpired)
		return
	}
	if !p.sawPeer {
		if now-p.start >= p.cfg.FirstPacket {
			p.abort(now, frame.ReasonIdle)
		}
		return
	}
	if now-p.lastProgress >= p.cfg.Idle {
		p.abort(now, frame.ReasonIdle)
	}
}

func (p *Peer) abort(now time.Duration, reason uint64) {
	if p.state == stAbort || p.state == stDone {
		return
	}
	p.state = stAbort
	p.reason = reason
	p.fail = &AbortError{Reason: reason}
	p.send(now, frame.Header{Type: frame.TypeABORT}, frame.EncodeAbort(reason))
	p.cleanup()
}

func (p *Peer) cleanup() {
	if p.cleaned {
		return
	}
	p.cleaned = true
	if p.hooks.Cleanup != nil {
		p.hooks.Cleanup()
	}
}

func (p *Peer) send(now time.Duration, h frame.Header, pt []byte) bool {
	if p.seq >= ^uint64(0)-1 {
		return false
	}
	p.seq++
	h.Seq = p.seq
	h.TransferID = p.cfg.TransferID
	h.SendTimeNS = uint64(now)
	d, err := p.sess.Seal(h, pt, p.cfg.LocalDir)
	if err != nil {
		return false
	}
	p.out = append(p.out, d)
	return true
}

func (p *Peer) rtt() time.Duration {
	if p.haveRTT && p.srtt > time.Millisecond {
		return p.srtt
	}
	return time.Millisecond
}

func (p *Peer) noteRTT(rtt, now time.Duration) {
	if rtt <= 0 {
		return
	}
	// RFC 6298: rttvar from the previous srtt, then srtt.
	if !p.haveRTT {
		p.srtt = rtt
		p.rttvar = rtt / 2
		p.haveRTT = true
	} else {
		d := p.srtt - rtt
		if d < 0 {
			d = -d
		}
		p.rttvar = (3*p.rttvar + d) / 4
		p.srtt = (7*p.srtt + rtt) / 8
	}
	if p.pacer != nil {
		p.pacer.OnRTT(rtt, now)
	}
}

func (p *Peer) emitPing(now time.Duration) {
	p.probe++
	p.send(now, frame.Header{Type: frame.TypePING, Offset: p.probe}, nil)
	p.pings++
	p.lastPing = now
}

// maybeRePing sends one fresh PING when this peer first hears the other,
// if every PING so far predates that. onPong drops those as stale.
func (p *Peer) maybeRePing(now time.Duration) {
	if !p.sawPeer || p.rePinged {
		return
	}
	p.rePinged = true
	if p.pings > 0 && p.lastPing < p.firstRx {
		p.emitPing(now)
	}
}

func (p *Peer) maybePing(now time.Duration) {
	if p.ponged && p.haveRTT && p.srtt < 10*time.Millisecond {
		return
	}
	if !p.ponged && p.pings >= 3 {
		if !p.extraPing && now-p.start >= time.Second {
			p.extraPing = true
			p.emitPing(now)
		}
		return
	}
	if p.ponged && p.pings >= 3 {
		return
	}
	if p.pings > 0 && now-p.lastPing < 10*time.Millisecond {
		return
	}
	if p.pings >= 3 {
		return
	}
	p.emitPing(now)
}

func (p *Peer) wantData() bool {
	if p.state != stSending && p.state != stFlushing {
		return false
	}
	return len(p.retx) > 0 || p.nextNew < p.cfg.Size
}

func (p *Peer) sendData(now time.Duration) {
	if p.pacer != nil {
		p.pacer.SetAppLimited(p.nextNew >= p.cfg.Size)
	}
	for {
		sp, retx, ok := p.nextSpan()
		if !ok {
			return
		}
		n := sp.End - sp.Start
		if p.pacer != nil && !p.pacer.CanSend(now, n) && !(retx && p.pacer.CanRepair(now, n)) {
			if retx {
				p.retx = append([]frame.Span{sp}, p.retx...)
			}
			return
		}
		if p.pacer == nil && p.unpaced {
			if retx {
				p.retx = append([]frame.Span{sp}, p.retx...)
			}
			return
		}
		if !retx && p.nextNew+n > p.cfg.ByteCap {
			p.abort(now, frame.ReasonByteCap)
			return
		}
		buf := make([]byte, n)
		if _, err := p.src.ReadAt(buf, int64(sp.Start)); err != nil {
			p.abort(now, frame.ReasonIO)
			return
		}
		flags := uint16(0)
		if retx {
			flags = frame.FlagRETX
		}
		if !p.send(now, frame.Header{Type: frame.TypeDATA, Flags: flags, Offset: sp.Start}, buf) {
			p.abort(now, frame.ReasonProtocol)
			return
		}
		p.inflight = append(p.inflight, sentSeg{start: sp.Start, end: sp.End, n: n, at: now, retx: retx})
		if p.pacer != nil {
			p.pacer.OnSend(n, now)
		} else {
			p.unpaced = true
		}
		if !retx {
			if _, err := p.hash.Write(buf); err != nil {
				p.abort(now, frame.ReasonIO)
				return
			}
			p.nextNew = sp.End
			if p.nextNew == p.cfg.Size && p.state == stSending {
				p.enterFlush(now)
			}
		}
	}
}

func (p *Peer) nextSpan() (frame.Span, bool, bool) {
	mss := p.cfg.MSS
	if len(p.retx) > 0 {
		sp := p.retx[0]
		p.retx = p.retx[1:]
		if sp.End-sp.Start > mss {
			rest := frame.Span{Start: sp.Start + mss, End: sp.End}
			sp.End = sp.Start + mss
			p.retx = append([]frame.Span{rest}, p.retx...)
		}
		return sp, true, true
	}
	if p.nextNew >= p.cfg.Size {
		return frame.Span{}, false, false
	}
	n := p.cfg.Size - p.nextNew
	if n > mss {
		n = mss
	}
	return frame.Span{Start: p.nextNew, End: p.nextNew + n}, false, true
}

func (p *Peer) enterFlush(now time.Duration) {
	if p.state == stFlushing || p.state == stDone || p.state == stAbort {
		return
	}
	p.state = stFlushing
}

// stalling reports segments in flight above contig with nothing queued
// for repair: only a stall probe can recover them if they are all lost.
func (p *Peer) stalling() bool {
	if p.state != stSending && p.state != stFlushing {
		return false
	}
	return len(p.inflight) > 0 && p.contig < p.nextNew && len(p.retx) == 0
}

// stallStart is the later of the last progress and the oldest in-flight
// send. The list is in send order.
func (p *Peer) stallStart() time.Duration {
	start := p.progAt
	if len(p.inflight) > 0 && p.inflight[0].at > start {
		start = p.inflight[0].at
	}
	return start
}

// stallWait is W = 2*max(srtt + 4*rttvar, FeedbackFloor) before the tail
// probe (1 s before the first RTT sample), then max(2*W, 1 s) before a
// range probe, doubled per range probe without progress, at most 8 s.
// docs/design.md section 4.5.
func (p *Peer) stallWait() time.Duration {
	w := time.Second
	if p.haveRTT {
		w = p.srtt + 4*p.rttvar
		if w < cc.FeedbackFloor {
			w = cc.FeedbackFloor
		}
		w *= 2
	}
	if p.probes == 0 {
		return w
	}
	w *= 2
	if w < time.Second {
		w = time.Second
	}
	for i := uint(1); i < p.probes && w < 8*time.Second; i++ {
		w *= 2
	}
	if w > 8*time.Second {
		w = 8 * time.Second
	}
	return w
}

// progress records an advance of contig or FEEDBACK delivered bytes. The
// next stall starts again at the tail probe.
func (p *Peer) progress(now time.Duration) {
	p.progAt = now
	p.probes = 0
	p.recheckAt = 0
}

// maybeStall is the stall probe (docs/design.md section 4.5). First a
// tail probe: the highest in-flight segment once, not a loss signal. If
// that brings no progress, a range probe: every segment older than the
// repair timeout is queued again, released, and counted as lost.
func (p *Peer) maybeStall(now time.Duration) {
	if p.noStall || !p.stalling() || now < p.recheckAt {
		return
	}
	if now-p.stallStart() < p.stallWait() {
		return
	}
	if p.probes == 0 {
		hi := p.inflight[0]
		for _, s := range p.inflight[1:] {
			if s.end > hi.end {
				hi = s
			}
		}
		p.retx = append(p.retx, frame.Span{Start: hi.start, End: hi.end})
		p.probes = 1
		p.progAt = now
		return
	}
	win := p.repairTimeout()
	release := make([]bool, len(p.inflight))
	var lost uint64
	var retry time.Duration
	for i, s := range p.inflight {
		if now-s.at < win {
			continue
		}
		sp := frame.Span{Start: s.start, End: s.end}
		if p.queueRetx(sp, now) {
			lost += sp.End - sp.Start
			release[i] = true
		} else if p.queued(sp) {
			release[i] = true
		} else if at := p.recentUntil(sp, now); retry == 0 || at < retry {
			retry = at
		}
	}
	if lost == 0 {
		// Every old range is refused by a younger overlapping send: wake
		// when that send ages out.
		p.recheckAt = retry
		return
	}
	var n uint64
	keep := p.inflight[:0]
	for i, s := range p.inflight {
		if release[i] {
			n += s.n
			continue
		}
		keep = append(keep, s)
	}
	p.inflight = keep
	if p.pacer != nil {
		p.pacer.OnFilled(n, now)
		p.pacer.OnLoss(lost, now)
	}
	p.wholeProbes++
	p.probes++
	p.progAt = now
	p.recheckAt = 0
}

func (p *Peer) maybeFIN(now time.Duration) {
	if p.finQueued && now-p.lastFIN < p.rtt() {
		return
	}
	flags := uint16(0)
	if p.closeAck {
		flags = frame.FlagCloseAck
	}
	if !p.send(now, frame.Header{Type: frame.TypeFIN, Flags: flags, Offset: p.cfg.Size}, nil) {
		// Only a spent sequence space fails a send: a wrap aborts the
		// grant, and WakeAt cannot keep returning now for a FIN.
		p.abort(now, frame.ReasonProtocol)
		return
	}
	p.finQueued = true
	p.lastFIN = now
}

// queueRetx queues sp for repair and reports whether it did.
func (p *Peer) queueRetx(sp frame.Span, now time.Duration) bool {
	if sp.End > p.nextNew {
		sp.End = p.nextNew
	}
	if sp.Start < p.contig {
		sp.Start = p.contig
	}
	if sp.Start >= sp.End {
		return false
	}
	if p.recent(sp, now) {
		return false
	}
	if p.queued(sp) {
		return false
	}
	p.retx = append(p.retx, sp)
	return true
}

// queued reports sp wholly inside ranges already queued for repair, such
// as a NACK hole inside a range probe's ranges.
func (p *Peer) queued(sp frame.Span) bool {
	return covered(sp, p.retx) == sp.End-sp.Start
}

// recent reports a send overlapping sp within the repair timeout, 2*srtt.
func (p *Peer) recent(sp frame.Span, now time.Duration) bool {
	return p.recentUntil(sp, now) > now
}

// recentUntil is when the youngest send overlapping sp ages past the
// repair timeout, or 0 if none is that young.
func (p *Peer) recentUntil(sp frame.Span, now time.Duration) time.Duration {
	win := p.repairTimeout()
	var until time.Duration
	for _, s := range p.inflight {
		if s.start < sp.End && s.end > sp.Start && now-s.at < win && s.at+win > until {
			until = s.at + win
		}
	}
	return until
}

func (p *Peer) noteContig(c uint64, now time.Duration) {
	if c > p.cfg.Size {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	if c <= p.contig {
		return
	}
	p.progress(now)
	// Filled segments leave the list, so it holds only what is in flight
	// and a scan costs the window, not the file.
	var filled uint64
	keep := p.inflight[:0]
	for _, s := range p.inflight {
		if s.end <= c {
			filled += s.n
			continue
		}
		keep = append(keep, s)
	}
	p.inflight = keep
	p.contig = c
	if p.pacer != nil && filled > 0 {
		p.pacer.OnFilled(filled, now)
	}
	// Drop retx that the receiver already has.
	dst := p.retx[:0]
	for _, sp := range p.retx {
		if sp.End <= c {
			continue
		}
		if sp.Start < c {
			sp.Start = c
		}
		dst = append(dst, sp)
	}
	p.retx = dst
}

func (p *Peer) onData(now time.Duration, h frame.Header, pt []byte) {
	if p.cfg.Sender || p.state == stDone {
		return
	}
	if uint64(len(pt)) > p.cfg.MSS {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	if p.cfg.Size == 0 || (len(pt) == 0 && p.cfg.Size > 0) {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	end, ok := add(h.Offset, uint64(len(pt)))
	if !ok || end > p.cfg.Size {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	if p.dest == nil {
		p.abort(now, frame.ReasonIO)
		return
	}
	for _, miss := range p.holes.Missing() {
		if miss.End <= h.Offset || miss.Start >= end {
			continue
		}
		lo := miss.Start
		if h.Offset > lo {
			lo = h.Offset
		}
		hi := miss.End
		if end < hi {
			hi = end
		}
		chunk := pt[lo-h.Offset : hi-h.Offset]
		if _, err := p.dest.WriteAt(chunk, int64(lo)); err != nil {
			p.abort(now, frame.ReasonIO)
			return
		}
	}
	newly, err := p.holes.Accept(h.Offset, end, h.Seq, now)
	if err != nil {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	if newly == 0 {
		return
	}
	if p.holes.Delivered() > p.cfg.ByteCap {
		p.abort(now, frame.ReasonByteCap)
		return
	}
	if h.Seq > p.highSeq {
		p.highSeq = h.Seq
		p.highSent = h.SendTimeNS
	}
	p.dataSinceFB++
	p.foldHash(now)
}

func (p *Peer) foldHash(now time.Duration) {
	c := p.holes.Contiguous()
	if c <= p.hashedTo {
		return
	}
	buf := make([]byte, c-p.hashedTo)
	if _, err := p.dest.ReadAt(buf, int64(p.hashedTo)); err != nil {
		p.abort(now, frame.ReasonIO)
		return
	}
	if _, err := p.hash.Write(buf); err != nil {
		p.abort(now, frame.ReasonIO)
		return
	}
	p.hashedTo = c
}

func (p *Peer) onNACK(now time.Duration, h frame.Header, pt []byte) {
	if !p.cfg.Sender || p.state == stDone {
		return
	}
	if h.Offset > p.cfg.Size {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	holes, err := frame.DecodeNACK(pt, p.cfg.Size)
	if err != nil {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	p.noteContig(h.Offset, now)
	// Newly lost bytes are the NACKed bytes not queued for repair and not
	// covered by a retransmission within the repair timeout. A re-NACK of a
	// hole under repair adds nothing; an older repair is released and
	// counts again.
	var lost uint64
	for _, sp := range holes {
		p.releaseForRetx(sp, now)
		lost += p.uncovered(sp)
		p.queueRetx(sp, now)
	}
	if p.pacer != nil && lost > 0 {
		p.pacer.OnLoss(lost, now)
	}
}

// uncovered is the bytes of sp outside every queued repair and every
// retransmission still in flight.
func (p *Peer) uncovered(sp frame.Span) uint64 {
	cov := append([]frame.Span(nil), p.retx...)
	for _, s := range p.inflight {
		if s.retx {
			cov = append(cov, frame.Span{Start: s.start, End: s.end})
		}
	}
	return sp.End - sp.Start - covered(sp, cov)
}

// covered is how many bytes of sp lie inside the union of spans.
func covered(sp frame.Span, spans []frame.Span) uint64 {
	var cov []frame.Span
	for _, c := range spans {
		if c.Start < sp.Start {
			c.Start = sp.Start
		}
		if c.End > sp.End {
			c.End = sp.End
		}
		if c.Start < c.End {
			cov = append(cov, c)
		}
	}
	sort.Slice(cov, func(i, j int) bool { return cov[i].Start < cov[j].Start })
	var n uint64
	at := sp.Start
	for _, c := range cov {
		if c.End <= at {
			continue
		}
		if c.Start < at {
			c.Start = at
		}
		n += c.End - c.Start
		at = c.End
	}
	return n
}

// repairTimeout is 2*srtt. A NACK shows the receiver as it was a one-way
// delay ago, and queueing can hold a repair past srtt; a repair younger
// than this is not presumed lost and its range is not sent again.
func (p *Peer) repairTimeout() time.Duration { return 2 * p.rtt() }

// releaseForRetx takes original sends of sp out of the inflight count,
// and retransmissions of sp older than the repair timeout, which are
// presumed lost. A younger retransmission stays until noteContig covers it.
func (p *Peer) releaseForRetx(sp frame.Span, now time.Duration) {
	var n uint64
	win := p.repairTimeout()
	keep := p.inflight[:0]
	for _, s := range p.inflight {
		if (!s.retx || now-s.at >= win) && s.start >= sp.Start && s.end <= sp.End {
			n += s.n
			continue
		}
		keep = append(keep, s)
	}
	p.inflight = keep
	if p.pacer != nil && n > 0 {
		p.pacer.OnFilled(n, now)
	}
}

func (p *Peer) onFeedback(now time.Duration, h frame.Header, pt []byte) {
	if !p.cfg.Sender || p.state == stDone {
		return
	}
	if h.Offset > p.cfg.Size {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	f, err := frame.DecodeFeedback(pt)
	if err != nil {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	p.noteContig(h.Offset, now)
	if p.pacer != nil {
		// A peer cannot have received more unique bytes than left here.
		d := f.DeliveredBytes
		if d > p.nextNew {
			d = p.nextNew
		}
		if d > p.fbDeliv {
			p.fbDeliv = d
			p.progress(now)
		}
		p.pacer.Sample(d, now)
		// newly_lost_bytes names the holes a NACK names; the NACK path
		// counts them once (docs/design.md section 6).
		if f.ECNCECount > 0 {
			p.pacer.OnECN(f.ECNCECount, now)
		}
	}
	// A repeated echo is not a sample: the same old send time on every
	// timer FEEDBACK would grow srtt, and the FIN retry with it.
	if f.EchoSendTimeNS > p.lastEcho && uint64(now) >= f.EchoSendTimeNS {
		p.lastEcho = f.EchoSendTimeNS
		p.noteRTT(now-time.Duration(f.EchoSendTimeNS), now)
	}
}

func (p *Peer) onFIN(now time.Duration, h frame.Header, pt []byte) {
	if p.cfg.Sender {
		return
	}
	if len(pt) != 0 || h.Offset != p.cfg.Size {
		p.abort(now, frame.ReasonSizeMismatch)
		return
	}
	p.holes.NoteFIN(h.Seq, now)
	p.finSeen = true
	if h.Flags&frame.FlagCloseAck != 0 && p.committed {
		p.gotClose = true
	}
}

func (p *Peer) onDONE(now time.Duration, h frame.Header, pt []byte) {
	if !p.cfg.Sender || p.state == stDone || p.state == stAbort {
		return
	}
	if h.Offset != p.cfg.Size || len(pt) != frame.HashLen {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	// A DONE before the last byte left, or a digest that is not this file,
	// is not success. Fail closed.
	if p.nextNew != p.cfg.Size {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	local := p.hash.Sum(nil)
	if !sameSum(local, pt) {
		p.abort(now, frame.ReasonHashMismatch)
		return
	}
	if p.cfg.HaveHash && !sameSum(p.cfg.ExpectHash[:], pt) {
		p.abort(now, frame.ReasonHashMismatch)
		return
	}
	p.state = stDone
	p.closeAck = true
	p.maybeFIN(now)
}

func (p *Peer) onAbort(h frame.Header, pt []byte) {
	if p.state == stDone {
		return
	}
	if h.Offset != 0 {
		p.state = stAbort
		p.reason = frame.ReasonProtocol
		p.fail = &AbortError{Reason: frame.ReasonProtocol}
		p.cleanup()
		return
	}
	reason, err := frame.DecodeAbort(pt)
	if err != nil {
		reason = frame.ReasonProtocol
	}
	p.state = stAbort
	p.reason = reason
	p.fail = &AbortError{Reason: reason}
	p.cleanup()
}

func (p *Peer) onPing(now time.Duration, h frame.Header, pt []byte) {
	if len(pt) != 0 {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	p.send(now, frame.Header{Type: frame.TypePONG, Offset: h.Offset}, frame.EncodePong(h.SendTimeNS, 0))
}

func (p *Peer) onPong(now time.Duration, h frame.Header, pt []byte) {
	echo, delay, err := frame.DecodePong(pt)
	if err != nil {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	stale := time.Duration(echo) < p.firstRx
	if !stale && uint64(now) >= echo+delay {
		p.noteRTT(now-time.Duration(echo)-time.Duration(delay), now)
	}
	if !p.cfg.Sender {
		return
	}
	p.ponged = true
	if p.state != stPinging {
		return
	}
	if p.cfg.Size == 0 || p.nextNew >= p.cfg.Size {
		p.enterFlush(now)
		p.progress(now)
		return
	}
	p.state = stSending
	p.progress(now)
}

func (p *Peer) maybeNACK(now time.Duration) {
	if !p.finSeen && p.holes.Empty() {
		return
	}
	mature := p.holes.Mature(now, p.srtt)
	if len(mature) == 0 {
		return
	}
	if len(mature) > frame.MaxNACKHoles {
		mature = mature[:frame.MaxNACKHoles]
	}
	// Mature is oldest first, so the cut keeps the oldest holes. Any accept
	// that ends inside a hole, including one that starts inside it,
	// re-births the remainder above it, so age is not offset order. A
	// NACK lists its holes in offset order (PROTOCOL 4.1).
	sort.Slice(mature, func(i, j int) bool { return mature[i].Start < mature[j].Start })
	var nb uint64
	for _, h := range mature {
		nb += h.End - h.Start
	}
	sig := nb ^ mature[0].Start ^ mature[len(mature)-1].End
	if p.nackSent && sig == p.nackSig && now-p.lastNACK < p.rtt() {
		return
	}
	pt, err := frame.EncodeNACK(mature)
	if err != nil {
		p.abort(now, frame.ReasonProtocol)
		return
	}
	if p.send(now, frame.Header{Type: frame.TypeNACK, Offset: p.holes.Contiguous()}, pt) {
		p.nackSent = true
		p.lastNACK = now
		p.nackSig = sig
	}
}

func (p *Peer) fbEvery() time.Duration {
	q := p.srtt / 4
	if q < cc.FeedbackFloor {
		return cc.FeedbackFloor
	}
	return q
}

func (p *Peer) maybeFeedback(now time.Duration) {
	if p.cfg.Size > 0 && p.holes.Delivered() == 0 {
		return
	}
	if p.fbSent && p.dataSinceFB < 64 && now-p.lastFB < p.fbEvery() {
		return
	}
	mature := p.holes.Mature(now, p.srtt)
	var lost uint64
	for _, h := range mature {
		lost += h.End - h.Start
	}
	newly := uint64(0)
	if lost > p.fbLost {
		newly = lost - p.fbLost
	}
	p.fbLost = lost
	var rate uint64
	if now > p.start {
		rate = uint64(float64(p.holes.Delivered()) / (now - p.start).Seconds())
	}
	// The echo is the highest-sequence DATA ever accepted, sent only when
	// some DATA was accepted since the previous FEEDBACK.
	var echo uint64
	if p.dataSinceFB > 0 {
		echo = p.highSent
	}
	f := frame.Feedback{
		EchoSendTimeNS: echo,
		DeliveredBytes: p.holes.Delivered(),
		NewlyLostBytes: newly,
		HighestSeq:     p.highSeq,
		RecvRateBps:    rate,
	}
	// The sender's sample includes this FEEDBACK's hold; its min filter
	// discards that.
	if p.send(now, frame.Header{Type: frame.TypeFEEDBACK, Offset: p.holes.Contiguous()}, frame.EncodeFeedback(f)) {
		p.fbSent = true
		p.lastFB = now
		p.dataSinceFB = 0
	}
}

func (p *Peer) maybeVerify(now time.Duration) {
	if p.committed || p.state == stAbort || !p.finSeen || !p.holes.Empty() {
		return
	}
	p.foldHash(now)
	if p.state == stAbort {
		return
	}
	if p.hashedTo != p.cfg.Size {
		return
	}
	sum := p.hash.Sum(nil)
	if p.cfg.HaveHash && !sameSum(sum, p.cfg.ExpectHash[:]) {
		p.abort(now, frame.ReasonHashMismatch)
		return
	}
	if p.cfg.Size == 0 {
		empty := sha256.Sum256(nil)
		if !sameSum(sum, empty[:]) {
			p.abort(now, frame.ReasonHashMismatch)
			return
		}
	}
	if p.hooks.Commit != nil {
		if err := p.hooks.Commit(); err != nil {
			p.abort(now, frame.ReasonIO)
			return
		}
	}
	p.committed = true
	p.doneSum = append([]byte(nil), sum...)
	p.maybeDONE(now)
}

// doneSum is the hash committed into DONE.
func (p *Peer) maybeDONE(now time.Duration) {
	if !p.committed || p.gotClose {
		return
	}
	if p.doneSent && now-p.lastDONE < p.rtt() {
		return
	}
	sum := p.doneSum
	if sum == nil {
		sum = p.hash.Sum(nil)
	}
	if p.send(now, frame.Header{Type: frame.TypeDONE, Offset: p.cfg.Size}, sum) {
		p.doneSent = true
		p.lastDONE = now
	}
}

// nextLen is the next DATA span without taking it off the retx queue.
func (p *Peer) nextLen() uint64 {
	mss := p.cfg.MSS
	if len(p.retx) > 0 {
		n := p.retx[0].End - p.retx[0].Start
		if n > mss {
			return mss
		}
		if n == 0 {
			return 1
		}
		return n
	}
	if p.nextNew >= p.cfg.Size {
		return 1
	}
	n := p.cfg.Size - p.nextNew
	if n > mss {
		return mss
	}
	return n
}

// sameSum compares two SHA-256 digests in constant time.
func sameSum(a, b []byte) bool {
	if len(a) != len(b) || len(a) != frame.HashLen {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func add(a, b uint64) (uint64, bool) {
	s := a + b
	if s < a {
		return 0, false
	}
	return s, true
}
