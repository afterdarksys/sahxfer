// Threats: the file bytes sit inside QUIC TLS and are not wrapped in a
// second AEAD. A short or long stream is protocol and does not commit.
// A hash that does not match does not commit. Cancel does not delete a
// file this transfer did not open. No paced peer.
package quic

import (
	"context"
	"crypto/sha256"
	"errors"
	"hash"
	"io"

	qgo "github.com/quic-go/quic-go"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/grant"
)

// Stream is one file on one QUIC connection. The sender writes the file,
// then reads a 32-byte SHA-256. The receiver does the opposite.
// Size 0 is an empty file. Src and Dest may be nil only when Size is 0.
type Stream struct {
	Conn    *qgo.Conn
	Sender  bool
	Size    uint64
	Expect  [32]byte
	Src     io.Reader
	Dest    io.Writer
	Commit  func() error
	Cleanup func()
}

// RunStream copies Size bytes and checks the grant hash.
// A size at or above 2^63 is too_large and does not call Cleanup.
func RunStream(ctx context.Context, s Stream) error {
	if s.Size >= 1<<63 {
		return code.New("too_large")
	}
	if s.Conn == nil {
		return code.New("internal")
	}
	if s.Size > 0 {
		if s.Sender && s.Src == nil {
			return code.New("internal")
		}
		if !s.Sender && s.Dest == nil {
			return code.New("internal")
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.Sender {
		return runSend(ctx, s)
	}
	return runRecv(ctx, s)
}

func runSend(ctx context.Context, s Stream) error {
	st, err := s.Conn.OpenUniStreamSync(ctx)
	if err != nil {
		return mapStream(err)
	}
	h := sha256.New()
	if err := writeReader(ctx, st, s.Src, s.Size, h); err != nil {
		return err
	}
	if err := st.Close(); err != nil {
		return mapStream(err)
	}
	rs, err := s.Conn.AcceptUniStream(ctx)
	if err != nil {
		return mapStream(err)
	}
	remote, err := readExact(ctx, rs, 32)
	if err != nil {
		return mapStream(err)
	}
	if err := readExtra(rs); err != nil {
		return err
	}
	sum := h.Sum(nil)
	var local, rem [32]byte
	copy(local[:], sum)
	copy(rem[:], remote)
	if !grant.SameHash(local, s.Expect) || !grant.SameHash(rem, s.Expect) {
		return code.New("hash_mismatch")
	}
	return nil
}

func runRecv(ctx context.Context, s Stream) error {
	st, err := s.Conn.AcceptUniStream(ctx)
	if err != nil {
		return mapStream(err)
	}
	h := sha256.New()
	buf := make([]byte, 32<<10)
	var got uint64
	for got < s.Size {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := s.Size - got
		if want > uint64(len(buf)) {
			want = uint64(len(buf))
		}
		n, err := st.Read(buf[:want])
		if n > 0 {
			if _, werr := h.Write(buf[:n]); werr != nil {
				s.cleanup()
				return code.New("io")
			}
			if werr := writeAll(ctx, s.Dest, buf[:n]); werr != nil {
				s.cleanup()
				return code.New("io")
			}
			got += uint64(n)
		}
		if got == s.Size {
			break
		}
		if err != nil {
			s.cleanup()
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return code.New("protocol")
			}
			return mapStream(err)
		}
		if n == 0 {
			s.cleanup()
			return code.New("io")
		}
	}
	var extra [1]byte
	n, err := st.Read(extra[:])
	if n > 0 {
		s.cleanup()
		return code.New("protocol")
	}
	if err == nil {
		s.cleanup()
		return code.New("io")
	}
	if !errors.Is(err, io.EOF) {
		s.cleanup()
		return mapStream(err)
	}
	var dig [32]byte
	copy(dig[:], h.Sum(nil))
	if !grant.SameHash(dig, s.Expect) {
		if serr := sendHash(ctx, s.Conn, dig); serr != nil {
			s.cleanup()
			return serr
		}
		s.cleanup()
		return code.New("hash_mismatch")
	}
	if s.Commit != nil {
		if cerr := s.Commit(); cerr != nil {
			s.cleanup()
			return code.New("io")
		}
	}
	if serr := sendHash(ctx, s.Conn, dig); serr != nil {
		return serr
	}
	return nil
}

func (s Stream) cleanup() {
	if s.Cleanup != nil {
		s.Cleanup()
	}
}

func sendHash(ctx context.Context, conn *qgo.Conn, dig [32]byte) error {
	st, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return mapStream(err)
	}
	if err := writeAll(ctx, st, dig[:]); err != nil {
		return mapStream(err)
	}
	if err := st.Close(); err != nil {
		return mapStream(err)
	}
	return nil
}

func writeReader(ctx context.Context, w io.Writer, r io.Reader, size uint64, h hash.Hash) error {
	if size == 0 {
		return nil
	}
	buf := make([]byte, 32<<10)
	var got uint64
	for got < size {
		if err := ctx.Err(); err != nil {
			return err
		}
		want := size - got
		if want > uint64(len(buf)) {
			want = uint64(len(buf))
		}
		n, err := r.Read(buf[:want])
		if n > 0 {
			if _, werr := h.Write(buf[:n]); werr != nil {
				return code.New("io")
			}
			if werr := writeAll(ctx, w, buf[:n]); werr != nil {
				return mapStream(werr)
			}
			got += uint64(n)
		}
		if got == size {
			return nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return code.New("protocol")
			}
			return mapStream(err)
		}
		if n == 0 {
			return code.New("io")
		}
	}
	return nil
}

func readExact(ctx context.Context, r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	got := 0
	for got < n {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		nr, err := r.Read(buf[got:])
		got += nr
		if got == n {
			return buf, nil
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if nr == 0 {
			return nil, code.New("io")
		}
	}
	return buf, nil
}

func readExtra(r io.Reader) error {
	var b [1]byte
	n, err := r.Read(b[:])
	if n > 0 {
		return code.New("protocol")
	}
	if err == nil {
		return code.New("io")
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return mapStream(err)
}

func writeAll(ctx context.Context, w io.Writer, p []byte) error {
	for len(p) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return code.New("io")
		}
	}
	return nil
}

func mapStream(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var ce *code.Error
	if errors.As(err, &ce) {
		return ce
	}
	return mapDial(err)
}
