package cli

// recv agent mode. The agent starts `recv --ctl-fd 3 --event-fd 4` as the
// identity user. Fd 3 carries agent-to-recv JSON lines: the grant, then
// renew and cancel. Fd 4 carries recv-to-agent JSON lines: ready, active,
// result. Never argv, never env, never disk.
//
// Threats: a grant line over the cap or with unknown fields; a renew that
// moves the lease deadline back; an agent that dies without cancelling
// (EOF on fd 3 is cancel); an agent that never renews (recv stops at the
// deadline it was given, even if the agent does not stop it); and the key
// or route token on fd 4, stdout, or stderr; an agent that never writes
// the grant (a 10 s read deadline, and a signal interrupts the read); an
// inherited fd that is a file or tty rather than a pipe or socket. The
// grant line buffer is wiped. json.Decoder copies the line into its own
// buffer, and the decoded strings are Go strings; neither can be wiped and
// both are left to the garbage collector.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/frame"
	"github.com/afterdarksys/sahxfer/internal/grant"
	"github.com/afterdarksys/sahxfer/internal/safeio"
	"github.com/afterdarksys/sahxfer/internal/udp"
)

// stopErr is why the agent-mode run was stopped from outside the engine.
type stopErr struct {
	status, reason string
}

func (e *stopErr) Error() string { return e.reason }

// cancelReasons are the reasons a cancel line may carry into the result.
// Anything else is reported as cancelled.
var cancelReasons = map[string]bool{
	"cancelled": true, "stopped": true, "expired": true, "idle": true,
	"policy": true, "auth": true, "byte_cap": true,
}

// grantWait is how long recv waits for the grant line on fd 3.
var grantWait = 10 * time.Second

type ctlMsg struct {
	Op       string
	Deadline int64
	Reason   string
}

type event struct {
	Ev         string  `json:"ev"`
	Op         string  `json:"op,omitempty"`
	UDP        string  `json:"udp,omitempty"`
	Rcvbuf     *int    `json:"rcvbuf,omitempty"`
	Bytes      *uint64 `json:"bytes,omitempty"`
	GrantID    string  `json:"grant_id,omitempty"`
	TransferID string  `json:"transfer_id,omitempty"`
	Status     string  `json:"status,omitempty"`
	Reason     string  `json:"reason,omitempty"`
	SHA256     string  `json:"sha256,omitempty"`
	Committed  *bool   `json:"committed,omitempty"`
}

type emitter struct {
	mu sync.Mutex
	w  io.Writer
}

// emit writes one line. A write error is ignored: the agent is gone, and
// the transfer outcome does not depend on it.
func (e *emitter) emit(ev event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, _ = e.w.Write(append(b, '\n'))
}

func recvAgent(ctx context.Context, ctlFD, evFD int, stdout io.Writer) error {
	evf, err := inheritedFD(evFD, "event")
	if err != nil {
		return err
	}
	defer evf.Close()
	em := &emitter{w: evf}
	fail := func(err error) error {
		no := false
		em.emit(event{Ev: "result", Status: "aborted", Reason: mapErr(err).Error(), Committed: &no})
		return err
	}
	ctl, err := inheritedFD(ctlFD, "ctl")
	if err != nil {
		return fail(err)
	}
	defer ctl.Close()

	line, rest, err := readGrantLine(ctx, ctl)
	if err != nil {
		return fail(err)
	}
	ag, err := grant.DecodeAgent(line, time.Now())
	wipe(line)
	if err != nil {
		// The grant id is not reported: nothing in the line is validated.
		return fail(err)
	}
	g := ag.Grant
	defer g.Wipe()

	runCtx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	msgs := make(chan ctlMsg)
	go readCtl(runCtx, io.MultiReader(bytes.NewReader(rest), ctl), msgs)
	go supervise(runCtx, stop, ag.Deadline, msgs, em)

	var committed bool
	var delivered uint64
	err = recvAgentRun(runCtx, ag, em, func(p *engine.Peer) {
		committed = p.Committed()
		delivered = p.Delivered()
	})
	status, reason := outcome(runCtx, err, committed)
	res := event{
		Ev: "result", GrantID: g.GrantID, TransferID: grant.TransferHex(g.TransferID),
		Status: status, Reason: reason, Bytes: &delivered, Committed: &committed,
	}
	if committed {
		res.SHA256 = hex.EncodeToString(g.Hash[:])
	}
	em.emit(res)
	if committed {
		return printOK(stdout, g)
	}
	if err == nil {
		err = code.New("internal")
	}
	if runCtx.Err() != nil {
		return code.New(reason)
	}
	return err
}

// recvAgentRun opens the root, binds or dials, emits ready, and runs the
// peer. done is called after the engine ran.
func recvAgentRun(ctx context.Context, ag *grant.AgentGrant, em *emitter, done func(*engine.Peer)) error {
	g := ag.Grant
	if err := g.Runnable(); err != nil {
		return err
	}
	if err := allowAgent(g); err != nil {
		return err
	}
	sender := g.Dir == "get"
	rootH, err := safeio.OpenRoot(g.Root)
	if err != nil {
		return err
	}
	defer rootH.Close()
	var src *os.File
	var temp *safeio.Temp
	if sender {
		src, err = rootH.OpenRegular(g.Path)
		if err != nil {
			return err
		}
		defer src.Close()
		n, err := fileSize(src)
		if err != nil {
			return err
		}
		if n != g.Size {
			return code.New("mismatch")
		}
		sum, err := hashFile(src, n)
		if err != nil {
			return err
		}
		if !grant.SameHash(sum, g.Hash) {
			return code.New("changed")
		}
	} else {
		temp, err = rootH.CreateTemp(g.Path, g.GrantID, g.Overwrite)
		if err != nil {
			return err
		}
		defer temp.Remove()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	listen := ag.Listen != ""
	conn, connected, err := bind(ag.Listen, ag.Dial, listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	rcv, snd := udp.TuneBuffers(conn, udp.WantBuffer)
	ready := event{Ev: "ready", Rcvbuf: &rcv}
	if listen {
		ready.UDP = conn.LocalAddr().String()
	}
	em.emit(ready)
	s := side{
		g: g, role: "agent", sender: sender,
		conn: conn, connected: connected,
		rcvbuf: rcv, sndbuf: snd,
		progress: func(n uint64) { em.emit(event{Ev: "active", Bytes: &n}) },
		done:     done,
	}
	if sender {
		s.src = src
	} else {
		s.dest = temp.File
		s.commit = func() error { return temp.Commit(g.Overwrite) }
		s.cleanup = func() { _ = temp.Remove() }
	}
	return transfer(ctx, s)
}

// outcome maps a run to the result status and reason. A commit is ok even
// when CLOSE_ACK never came or a stop arrived afterwards.
func outcome(ctx context.Context, err error, committed bool) (status, reason string) {
	if committed {
		return "ok", ""
	}
	if ctx.Err() != nil {
		var se *stopErr
		if errors.As(context.Cause(ctx), &se) {
			return se.status, se.reason
		}
		return "aborted", "stopped"
	}
	if err == nil {
		return "aborted", "protocol"
	}
	name := mapErr(err).Error()
	var ae *engine.AbortError
	if errors.As(err, &ae) {
		name = frame.ReasonName(ae.Reason)
	}
	switch name {
	case "hash_mismatch":
		return "hash_mismatch", name
	case "expired":
		return "expired", name
	case "io", "no_space":
		return "io_error", name
	}
	return "aborted", name
}

// supervise turns fd 3 lines and the lease deadline into a stop. A renew
// may only move the deadline forward; one that does not is refused with a
// refused event on fd 4 and the deadline stays. EOF is cancel with reason
// stopped. The deadline lapsing stops the run as expired, whether or not
// the agent says so.
func supervise(ctx context.Context, stop context.CancelCauseFunc, deadline time.Time, msgs <-chan ctlMsg, em *emitter) {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			stop(&stopErr{status: "expired", reason: "expired"})
			return
		case m, ok := <-msgs:
			if !ok {
				stop(&stopErr{status: "aborted", reason: "stopped"})
				return
			}
			switch m.Op {
			case "renew":
				next := time.Unix(m.Deadline, 0)
				if !next.After(deadline) {
					em.emit(event{Ev: "refused", Op: "renew", Reason: "deadline_not_forward"})
					continue
				}
				deadline = next
				timer.Reset(time.Until(deadline))
			case "cancel":
				reason := m.Reason
				if !cancelReasons[reason] {
					reason = "cancelled"
				}
				stop(&stopErr{status: "aborted", reason: reason})
				return
			default:
				stop(&stopErr{status: "aborted", reason: "protocol"})
				return
			}
		}
	}
}

// readCtl decodes one control line at a time. A malformed or oversize line
// is sent as an unknown op, which stops the run. EOF closes msgs.
func readCtl(ctx context.Context, r io.Reader, msgs chan<- ctlMsg) {
	defer close(msgs)
	br := bufio.NewReaderSize(r, grant.MaxAgentLine+1)
	for {
		line, err := br.ReadSlice('\n')
		if err != nil {
			if len(line) > 0 || !errors.Is(err, io.EOF) {
				select {
				case msgs <- ctlMsg{Op: "bad"}:
				case <-ctx.Done():
				}
			}
			return
		}
		m := parseCtl(line)
		select {
		case msgs <- m:
		case <-ctx.Done():
			return
		}
	}
}

// parseCtl accepts exactly {"op":"renew","deadline_unix":<n>} and
// {"op":"cancel"} with an optional "reason". Any other key, a renew with a
// reason, or a missing or non-positive deadline is op "bad".
func parseCtl(line []byte) ctlMsg {
	bad := ctlMsg{Op: "bad"}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(line))
	if dec.Decode(&raw) != nil || dec.More() {
		return bad
	}
	var m ctlMsg
	if json.Unmarshal(raw["op"], &m.Op) != nil {
		return bad
	}
	switch m.Op {
	case "renew":
		if len(raw) != 2 || json.Unmarshal(raw["deadline_unix"], &m.Deadline) != nil || m.Deadline <= 0 {
			return bad
		}
	case "cancel":
		r, ok := raw["reason"]
		if len(raw) > 2 || (len(raw) == 2 && !ok) || (ok && json.Unmarshal(r, &m.Reason) != nil) {
			return bad
		}
	default:
		return bad
	}
	return m
}

// readGrantLine waits at most grantWait for the grant line. A done ctx
// (SIGTERM, interrupt) ends the wait at once as cancelled; the deadline
// passing is bad_grant. The deadline is cleared before returning.
func readGrantLine(ctx context.Context, ctl *os.File) (line, rest []byte, err error) {
	if err := ctl.SetReadDeadline(time.Now().Add(grantWait)); err != nil {
		return nil, nil, code.New("io")
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = ctl.SetReadDeadline(time.Now())
		case <-done:
		}
	}()
	line, rest, err = readFirstLine(ctl)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, code.New("cancelled")
		}
		return nil, nil, err
	}
	if err := ctl.SetReadDeadline(time.Time{}); err != nil {
		wipe(line)
		return nil, nil, code.New("io")
	}
	return line, rest, nil
}

// readFirstLine reads up to the first newline into one fixed buffer, so
// the grant (key included) is never copied by a growing slice. line
// aliases that buffer; the caller wipes it. rest is a copy of what followed.
func readFirstLine(r io.Reader) (line, rest []byte, err error) {
	buf := make([]byte, grant.MaxAgentLine+1)
	n := 0
	for {
		if i := bytes.IndexByte(buf[:n], '\n'); i >= 0 {
			rest = append([]byte(nil), buf[i+1:n]...)
			wipe(buf[i:n])
			return buf[:i], rest, nil
		}
		if n == len(buf) {
			wipe(buf)
			return nil, nil, code.New("too_large")
		}
		m, rerr := r.Read(buf[n:])
		n += m
		if rerr != nil && m == 0 {
			wipe(buf)
			if errors.Is(rerr, io.EOF) || errors.Is(rerr, os.ErrDeadlineExceeded) {
				return nil, nil, code.New("bad_grant")
			}
			return nil, nil, code.New("io")
		}
	}
}

// recvSweep reads {root, path, grant_id} from the control fd and removes
// only .sahxfer-<grant_id>.part beside that path.
// recvSweep removes the one temp name the grant id fixes. With an event fd
// (--report) it then reports the target: one line {"ev":"target","bytes",
// "sha256"} when it is a regular file, nothing when it does not exist, so
// the agent can tell a commit that happened before a restart from one that
// did not. Any other failure is an error, and the agent records the outcome
// as unknown.
func recvSweep(ctx context.Context, ctlFD, evFD int) error {
	ctl, err := inheritedFD(ctlFD, "ctl")
	if err != nil {
		return err
	}
	defer ctl.Close()
	line, _, err := readGrantLine(ctx, ctl)
	if err != nil {
		return err
	}
	var doc struct {
		Root    string `json:"root"`
		Path    string `json:"path"`
		GrantID string `json:"grant_id"`
	}
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	if dec.Decode(&doc) != nil || dec.More() {
		return code.New("bad_grant")
	}
	rootH, err := safeio.OpenRoot(doc.Root)
	if err != nil {
		return err
	}
	defer rootH.Close()
	if err := rootH.RemoveTemp(doc.Path, doc.GrantID); err != nil || evFD < 0 {
		return err
	}
	evf, err := inheritedFD(evFD, "event")
	if err != nil {
		return err
	}
	defer evf.Close()
	f, err := rootH.OpenRegular(doc.Path)
	if err != nil {
		if e, ok := err.(*code.Error); ok && e.C == "not_found" {
			return nil
		}
		return err
	}
	defer f.Close()
	n, err := fileSize(f)
	if err != nil {
		return err
	}
	sum, err := hashFile(f, n)
	if err != nil {
		return err
	}
	b, err := json.Marshal(event{Ev: "target", Bytes: &n, SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		return code.New("io")
	}
	if _, err := evf.Write(append(b, '\n')); err != nil {
		return code.New("io")
	}
	return nil
}
