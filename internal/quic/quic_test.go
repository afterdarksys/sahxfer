package quic

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	qgo "github.com/quic-go/quic-go"

	"github.com/afterdarksys/sahxfer/internal/code"
	"github.com/afterdarksys/sahxfer/internal/engine"
	"github.com/afterdarksys/sahxfer/internal/frame"
	"github.com/afterdarksys/sahxfer/internal/seal"
	"github.com/afterdarksys/sahxfer/internal/udp"
)

func testMaterial() ([]byte, []byte) {
	return bytes.Repeat([]byte("K"), seal.KeySize), bytes.Repeat([]byte("T"), seal.TokenSize)
}

type memFile struct {
	b []byte
}

func (m *memFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(m.b)) {
		return 0, io.ErrUnexpectedEOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, io.ErrUnexpectedEOF
	}
	return n, nil
}

func (m *memFile) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, io.ErrUnexpectedEOF
	}
	end := int(off) + len(p)
	if end > len(m.b) {
		nb := make([]byte, end)
		copy(nb, m.b)
		m.b = nb
	}
	copy(m.b[off:], p)
	return len(p), nil
}

type ends struct {
	s, r            *engine.Peer
	dst             *memFile
	commits, cleans int
}

func newPeers(t *testing.T, file []byte, transport string) *ends {
	t.Helper()
	key, tok := testMaterial()
	sum := sha256.Sum256(file)
	sc := engine.Config{
		TransferID:  7,
		Size:        uint64(len(file)),
		MSS:         frame.InternetPlaintext,
		Key:         append([]byte(nil), key...),
		Token:       append([]byte(nil), tok...),
		LocalDir:    seal.DirClient,
		PeerDir:     seal.DirAgent,
		Sender:      true,
		Transport:   transport,
		Pacing:      false,
		HaveHash:    true,
		ExpectHash:  sum,
		Idle:        5 * time.Second,
		Max:         20 * time.Second,
		FirstPacket: 2 * time.Second,
	}
	rc := sc
	rc.Key = append([]byte(nil), key...)
	rc.Token = append([]byte(nil), tok...)
	rc.LocalDir = seal.DirAgent
	rc.PeerDir = seal.DirClient
	rc.Sender = false
	s, err := engine.New(sc)
	if err != nil {
		t.Fatal(err)
	}
	r, err := engine.New(rc)
	if err != nil {
		t.Fatal(err)
	}
	e := &ends{s: s, r: r, dst: &memFile{}}
	if err := s.AttachSource(&memFile{b: append([]byte(nil), file...)}); err != nil {
		t.Fatal(err)
	}
	r.AttachDest(e.dst)
	s.SetHooks(engine.Hooks{Cleanup: func() { e.cleans++ }})
	r.SetHooks(engine.Hooks{
		Commit:  func() error { e.commits++; return nil },
		Cleanup: func() { e.cleans++ },
	})
	return e
}

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
	return cert, pool, sum[:]
}

func pairConn(t *testing.T, datagram bool) (server, client *qgo.Conn) {
	t.Helper()
	cert, roots, _ := testCert(t)
	var listenConf, dialConf *qgo.Config
	if datagram {
		listenConf = DatagramConf()
		dialConf = DatagramConf()
	} else {
		listenConf = StreamConf()
		dialConf = StreamConf()
	}
	ln, err := Listen("127.0.0.1:0", ServerConfig(cert), listenConf)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	acc := make(chan *qgo.Conn, 1)
	errc := make(chan error, 1)
	go func() {
		c, aerr := ln.Accept(ctx)
		if aerr != nil {
			errc <- aerr
			return
		}
		acc <- c
	}()
	t.Cleanup(func() {
		cancel()
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("listener: %v", err)
		}
	})
	tlsCli, err := ClientConfig("127.0.0.1", roots, nil)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	cli, err := Dial(dctx, ln.Addr().String(), tlsCli, dialConf)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case server = <-acc:
	case err := <-errc:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("accept")
	}
	t.Cleanup(func() {
		closeConn(server)
		closeConn(cli)
	})
	return server, cli
}

func closeConn(c *qgo.Conn) {
	if c == nil {
		return
	}
	err := c.CloseWithError(0, "")
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return
	}
}

func pingPkt(id uint64, token []byte) []byte {
	var rt [16]byte
	copy(rt[:], token)
	p := make([]byte, frame.Overhead)
	frame.Put(p, frame.Header{
		Version:    frame.Version,
		Type:       frame.TypePING,
		TransferID: id,
		RouteToken: rt,
	})
	return p
}

func mustAuthDial(t *testing.T, tlsConf *tls.Config, conf *qgo.Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Dial(ctx, "127.0.0.1:1", tlsConf, conf)
	if err == nil || err.Error() != "auth" {
		t.Fatalf("%v", err)
	}
}

func freshTLS(t *testing.T) *tls.Config {
	t.Helper()
	c, err := ClientConfig("127.0.0.1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPacingRejected(t *testing.T) {
	_, err := engine.New(engine.Config{Transport: engine.TransportQUICDatagram, Pacing: true})
	if err == nil || err.Error() != "sahxfer: pacing" {
		t.Fatalf("%v", err)
	}
	dc := DatagramConf()
	if dc.Allow0RTT || !dc.EnableDatagrams {
		t.Fatalf("allow=%v dgrams=%v", dc.Allow0RTT, dc.EnableDatagrams)
	}
	if len(dc.Versions) != 1 || dc.Versions[0] != qgo.Version1 {
		t.Fatalf("%v", dc.Versions)
	}
	if dc.MaxIncomingStreams >= 0 || dc.MaxIncomingUniStreams >= 0 {
		t.Fatalf("streams %d %d", dc.MaxIncomingStreams, dc.MaxIncomingUniStreams)
	}
	cfg := freshTLS(t)
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("tls %x %x", cfg.MinVersion, cfg.MaxVersion)
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != ALPN {
		t.Fatalf("%v", cfg.NextProtos)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("skip")
	}
}

func TestDialRejects(t *testing.T) {
	t.Run("skip", func(t *testing.T) {
		c := freshTLS(t)
		c.InsecureSkipVerify = true
		mustAuthDial(t, c, DatagramConf())
	})
	t.Run("alpn", func(t *testing.T) {
		c := freshTLS(t)
		c.NextProtos = []string{"h3"}
		mustAuthDial(t, c, DatagramConf())
	})
	t.Run("version", func(t *testing.T) {
		c := freshTLS(t)
		c.MinVersion = tls.VersionTLS12
		c.MaxVersion = tls.VersionTLS12
		mustAuthDial(t, c, DatagramConf())
	})
	t.Run("0rtt", func(t *testing.T) {
		q := DatagramConf()
		q.Allow0RTT = true
		mustAuthDial(t, freshTLS(t), q)
	})
	t.Run("versions", func(t *testing.T) {
		for _, vs := range [][]qgo.Version{
			nil,
			{},
			{qgo.Version2},
			{qgo.Version1, qgo.Version2},
		} {
			q := DatagramConf()
			q.Versions = vs
			mustAuthDial(t, freshTLS(t), q)
		}
	})
	t.Run("nil", func(t *testing.T) {
		mustAuthDial(t, nil, DatagramConf())
		mustAuthDial(t, freshTLS(t), nil)
	})
}

func TestClientConfigPin(t *testing.T) {
	if _, err := ClientConfig("127.0.0.1", nil, make([]byte, 31)); err == nil || err.Error() != "auth" {
		t.Fatalf("%v", err)
	}
	if _, err := ClientConfig("127.0.0.1", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ClientConfig("127.0.0.1", nil, []byte{}); err != nil {
		t.Fatal(err)
	}
}

func TestMapDial(t *testing.T) {
	if mapDial(&qgo.HandshakeTimeoutError{}).Error() != "io" {
		t.Fatal(mapDial(&qgo.HandshakeTimeoutError{}))
	}
	if mapDial(&qgo.VersionNegotiationError{}).Error() != "auth" {
		t.Fatal(mapDial(&qgo.VersionNegotiationError{}))
	}
	if mapDial(&qgo.TransportError{ErrorCode: 0x100}).Error() != "auth" {
		t.Fatal(mapDial(&qgo.TransportError{ErrorCode: 0x100}))
	}
	if mapDial(&qgo.DatagramTooLargeError{}).Error() != "protocol" {
		t.Fatal(mapDial(&qgo.DatagramTooLargeError{}))
	}
	if !errors.Is(mapDial(context.Canceled), context.Canceled) {
		t.Fatal(mapDial(context.Canceled))
	}
	ce := code.New("auth")
	if mapDial(ce) != ce {
		t.Fatalf("%v", mapDial(ce))
	}
}

func TestALPNMismatch(t *testing.T) {
	cert, roots, _ := testCert(t)
	ln, err := Listen("127.0.0.1:0", ServerConfig(cert), DatagramConf())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		c, aerr := ln.Accept(ctx)
		if aerr != nil {
			return
		}
		closeConn(c)
	}()
	defer func() {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("listener: %v", err)
		}
	}()
	raw := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
		RootCAs:    roots,
		ServerName: "127.0.0.1",
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	_, err = qgo.DialAddr(dctx, ln.Addr().String(), raw, DatagramConf())
	if err == nil {
		t.Fatal("dial")
	}
	if mapDial(err).Error() != "auth" {
		t.Fatalf("%T %v", err, err)
	}
}

func TestVerifyPinAndName(t *testing.T) {
	cert, roots, pin := testCert(t)
	ln, err := Listen("127.0.0.1:0", ServerConfig(cert), DatagramConf())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var held []*qgo.Conn
	go func() {
		for {
			c, aerr := ln.Accept(ctx)
			if aerr != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			closeConn(c)
		}
	}()
	defer func() {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("listener: %v", err)
		}
	}()
	addr := ln.Addr().String()
	good, err := ClientConfig("127.0.0.1", roots, pin)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := Dial(dctx, addr, good, DatagramConf())
	dcancel()
	if err != nil {
		t.Fatal(err)
	}
	closeConn(conn)

	badPin := append([]byte(nil), pin...)
	badPin[0] ^= 0xff
	bad, err := ClientConfig("127.0.0.1", roots, badPin)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel = context.WithTimeout(context.Background(), 5*time.Second)
	_, err = Dial(dctx, addr, bad, DatagramConf())
	dcancel()
	if err == nil || err.Error() != "auth" {
		t.Fatalf("%v", err)
	}

	named, err := ClientConfig("not-the-host.example", roots, pin)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel = context.WithTimeout(context.Background(), 5*time.Second)
	_, err = Dial(dctx, addr, named, DatagramConf())
	dcancel()
	if err == nil || err.Error() != "auth" {
		t.Fatalf("%v", err)
	}
}

func TestDatagramCopy(t *testing.T) {
	for _, file := range [][]byte{bytes.Repeat([]byte("abc"), 1700), nil} {
		file := file
		t.Run(nameOf(file), func(t *testing.T) {
			e := newPeers(t, file, engine.TransportQUICDatagram)
			srv, cli := pairConn(t, true)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			errc := make(chan error, 1)
			go func() { errc <- RunDatagram(ctx, Datagram{Peer: e.r, Conn: srv}) }()
			time.Sleep(20 * time.Millisecond)
			txErr := RunDatagram(ctx, Datagram{Peer: e.s, Conn: cli})
			rxErr := <-errc
			if txErr != nil || rxErr != nil {
				t.Fatalf("tx=%v rx=%v", txErr, rxErr)
			}
			if e.commits != 1 || e.cleans != 0 || !bytes.Equal(e.dst.b, file) {
				t.Fatalf("commits=%d cleans=%d n=%d", e.commits, e.cleans, len(e.dst.b))
			}
		})
	}
}

func TestRunDatagramNil(t *testing.T) {
	if err := RunDatagram(context.Background(), Datagram{}); err == nil || err.Error() != "internal" {
		t.Fatalf("%v", err)
	}
	key, tok := testMaterial()
	p, err := engine.New(engine.Config{
		Transport: engine.TransportQUICDatagram,
		Key:       key,
		Token:     tok,
		LocalDir:  seal.DirClient,
		PeerDir:   seal.DirAgent,
		Sender:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := RunDatagram(context.Background(), Datagram{Peer: p}); err == nil || err.Error() != "internal" {
		t.Fatalf("%v", err)
	}
	_, cli := pairConn(t, true)
	if err := RunDatagram(context.Background(), Datagram{Conn: cli}); err == nil || err.Error() != "internal" {
		t.Fatalf("%v", err)
	}
}

func nameOf(file []byte) string {
	if len(file) == 0 {
		return "empty"
	}
	return "file"
}

func TestStreamCopy(t *testing.T) {
	for _, file := range [][]byte{bytes.Repeat([]byte("abc"), 1700), nil} {
		file := file
		t.Run(nameOf(file), func(t *testing.T) {
			srv, cli := pairConn(t, false)
			sum := sha256.Sum256(file)
			var commits, cleans, scleans int
			var dst bytes.Buffer
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			errc := make(chan error, 1)
			go func() {
				errc <- RunStream(ctx, Stream{
					Conn:    srv,
					Size:    uint64(len(file)),
					Expect:  sum,
					Dest:    &dst,
					Commit:  func() error { commits++; return nil },
					Cleanup: func() { cleans++ },
				})
			}()
			time.Sleep(20 * time.Millisecond)
			txErr := RunStream(ctx, Stream{
				Conn:    cli,
				Sender:  true,
				Size:    uint64(len(file)),
				Expect:  sum,
				Src:     bytes.NewReader(file),
				Cleanup: func() { scleans++ },
			})
			rxErr := <-errc
			if txErr != nil || rxErr != nil {
				t.Fatalf("tx=%v rx=%v", txErr, rxErr)
			}
			if commits != 1 || cleans != 0 || scleans != 0 || !bytes.Equal(dst.Bytes(), file) {
				t.Fatalf("commits=%d cleans=%d scleans=%d n=%d", commits, cleans, scleans, dst.Len())
			}
		})
	}
}

func TestStreamTooLarge(t *testing.T) {
	var cleans int
	err := RunStream(context.Background(), Stream{Size: 1 << 63, Cleanup: func() { cleans++ }})
	if err == nil || err.Error() != "too_large" || cleans != 0 {
		t.Fatalf("%v cleans=%d", err, cleans)
	}
}

func TestStreamShort(t *testing.T) {
	rawLen(t, 100, 99)
}

func TestStreamLong(t *testing.T) {
	rawLen(t, 100, 101)
}

func rawLen(t *testing.T, size, n int) {
	t.Helper()
	srv, cli := pairConn(t, false)
	var commits, cleans int
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		st, err := cli.OpenUniStreamSync(ctx)
		if err != nil {
			return
		}
		p := bytes.Repeat([]byte("x"), n)
		for len(p) > 0 {
			w, werr := st.Write(p)
			if werr != nil {
				return
			}
			if w == 0 {
				return
			}
			p = p[w:]
		}
		if err := st.Close(); err != nil {
			return
		}
	}()
	err := RunStream(ctx, Stream{
		Conn:    srv,
		Size:    uint64(size),
		Dest:    &bytes.Buffer{},
		Commit:  func() error { commits++; return nil },
		Cleanup: func() { cleans++ },
	})
	if err == nil || err.Error() != "protocol" || cleans != 1 || commits != 0 {
		t.Fatalf("%v cleans=%d commits=%d", err, cleans, commits)
	}
}

func TestStreamHashMismatch(t *testing.T) {
	file := []byte("nope")
	srv, cli := pairConn(t, false)
	var commits, cleans, scleans int
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errc := make(chan error, 2)
	go func() {
		errc <- RunStream(ctx, Stream{
			Conn:    srv,
			Size:    uint64(len(file)),
			Dest:    &bytes.Buffer{},
			Commit:  func() error { commits++; return nil },
			Cleanup: func() { cleans++ },
		})
	}()
	time.Sleep(20 * time.Millisecond)
	go func() {
		errc <- RunStream(ctx, Stream{
			Conn:    cli,
			Sender:  true,
			Size:    uint64(len(file)),
			Src:     bytes.NewReader(file),
			Cleanup: func() { scleans++ },
		})
	}()
	var got []error
	for range 2 {
		select {
		case err := <-errc:
			got = append(got, err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if len(got) != 2 || got[0] == nil || got[1] == nil || got[0].Error() != "hash_mismatch" || got[1].Error() != "hash_mismatch" {
		t.Fatalf("%v", got)
	}
	if cleans != 1 || commits != 0 || scleans != 0 {
		t.Fatalf("cleans=%d commits=%d scleans=%d", cleans, commits, scleans)
	}
}

func TestStreamCommitFail(t *testing.T) {
	file := bytes.Repeat([]byte("c"), 100)
	sum := sha256.Sum256(file)
	srv, cli := pairConn(t, false)
	var commits, cleans int
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		st, err := cli.OpenUniStreamSync(ctx)
		if err != nil {
			return
		}
		p := file
		for len(p) > 0 {
			w, werr := st.Write(p)
			if werr != nil {
				return
			}
			if w == 0 {
				return
			}
			p = p[w:]
		}
		if err := st.Close(); err != nil {
			return
		}
	}()
	err := RunStream(ctx, Stream{
		Conn:   srv,
		Size:   uint64(len(file)),
		Expect: sum,
		Dest:   &bytes.Buffer{},
		Commit: func() error {
			commits++
			return errors.New("fail")
		},
		Cleanup: func() { cleans++ },
	})
	if err == nil || err.Error() != "io" || strings.Contains(err.Error(), "fail") || commits != 1 || cleans != 1 {
		t.Fatalf("%v commits=%d cleans=%d", err, commits, cleans)
	}
}

func TestStreamCancel(t *testing.T) {
	srv, cli := pairConn(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	var cleans int
	errc := make(chan error, 1)
	go func() {
		errc <- RunStream(ctx, Stream{
			Conn:    srv,
			Size:    10,
			Dest:    &bytes.Buffer{},
			Cleanup: func() { cleans++ },
		})
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) || cleans != 0 {
			t.Fatalf("%v cleans=%d", err, cleans)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hung")
	}
	closeConn(cli)
	closeConn(srv)
}

func TestStreamNil(t *testing.T) {
	if err := RunStream(context.Background(), Stream{}); err == nil || err.Error() != "internal" {
		t.Fatalf("%v", err)
	}
	if err := RunStream(context.Background(), Stream{Size: 0}); err == nil || err.Error() != "internal" {
		t.Fatalf("%v", err)
	}
	srv, _ := pairConn(t, false)
	var cleans int
	err := RunStream(context.Background(), Stream{
		Conn:    srv,
		Sender:  true,
		Size:    10,
		Cleanup: func() { cleans++ },
	})
	if err == nil || err.Error() != "internal" || cleans != 0 {
		t.Fatalf("%v cleans=%d", err, cleans)
	}
	err = RunStream(context.Background(), Stream{
		Conn:    srv,
		Size:    10,
		Cleanup: func() { cleans++ },
	})
	if err == nil || err.Error() != "internal" || cleans != 0 {
		t.Fatalf("%v cleans=%d", err, cleans)
	}
}

func serveBridge(t *testing.T, cert tls.Certificate, report func(uint64, string)) (*Bridge, *qgo.Listener, *net.UDPConn) {
	t.Helper()
	ln, err := Listen("127.0.0.1:0", ServerConfig(cert), DatagramConf())
	if err != nil {
		t.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	b := New()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- b.Serve(ctx, ln, uc, report) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("serve did not return")
		}
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("listener: %v", err)
		}
		if err := uc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("udp: %v", err)
		}
	})
	return b, ln, uc
}

func TestBridgeCopy(t *testing.T) {
	for _, file := range [][]byte{bytes.Repeat([]byte("abc"), 1700), nil} {
		file := file
		t.Run(nameOf(file), func(t *testing.T) {
			cert, roots, _ := testCert(t)
			b, ln, uc := serveBridge(t, cert, nil)
			_, tok := testMaterial()
			exp := time.Duration(time.Now().Add(2 * time.Minute).UnixNano())
			if err := b.Admit(7, tok, uint64(len(file))*32, exp); err != nil {
				t.Fatal(err)
			}
			tlsCli, err := ClientConfig("127.0.0.1", roots, nil)
			if err != nil {
				t.Fatal(err)
			}
			dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
			cli, err := Dial(dctx, ln.Addr().String(), tlsCli, DatagramConf())
			dcancel()
			if err != nil {
				t.Fatal(err)
			}
			defer closeConn(cli)
			agent, err := net.DialUDP("udp", nil, uc.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := agent.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Errorf("agent: %v", err)
				}
			}()
			e := newPeers(t, file, engine.TransportQUICBridge)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			errc := make(chan error, 1)
			go func() {
				errc <- udp.Run(ctx, udp.Config{Peer: e.r, Conn: agent, Connected: true})
			}()
			time.Sleep(20 * time.Millisecond)
			txErr := RunDatagram(ctx, Datagram{Peer: e.s, Conn: cli})
			rxErr := <-errc
			if txErr != nil || rxErr != nil {
				t.Fatalf("tx=%v rx=%v", txErr, rxErr)
			}
			if e.commits != 1 || e.cleans != 0 || !bytes.Equal(e.dst.b, file) {
				t.Fatalf("commits=%d cleans=%d n=%d", e.commits, e.cleans, len(e.dst.b))
			}
		})
	}
}

func TestBridgeQueue(t *testing.T) {
	b := New()
	const id = uint64(7)
	chunk := make([]byte, 64<<10)
	n := 0
	for n < 80 && b.room(id) {
		b.enqueueUDP("127.0.0.1:9", id, chunk)
		n++
	}
	if n != 64 || b.room(id) || !b.room(9) || QueueCap != 4<<20 {
		t.Fatalf("n=%d room=%v other=%v cap=%d", n, b.room(id), b.room(9), QueueCap)
	}
	b.mu.Lock()
	got := b.grantBytes[id]
	b.mu.Unlock()
	if got != QueueCap {
		t.Fatalf("bytes=%d", got)
	}
}

func TestBridgeWrongToken(t *testing.T) {
	cert, roots, _ := testCert(t)
	type rep struct {
		id   uint64
		code string
	}
	ch := make(chan rep, 4)
	b, ln, uc := serveBridge(t, cert, func(id uint64, code string) {
		select {
		case ch <- rep{id, code}:
		default:
		}
	})
	if uc.LocalAddr() == nil {
		t.Fatal("udp")
	}
	_, tok := testMaterial()
	exp := time.Duration(time.Now().Add(2 * time.Minute).UnixNano())
	if err := b.Admit(7, tok, 0, exp); err != nil {
		t.Fatal(err)
	}
	tlsCli, err := ClientConfig("127.0.0.1", roots, nil)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	cli, err := Dial(dctx, ln.Addr().String(), tlsCli, DatagramConf())
	dcancel()
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn(cli)
	time.Sleep(50 * time.Millisecond)
	pkt := pingPkt(7, bytes.Repeat([]byte("X"), seal.TokenSize))
	stop := time.AfterFunc(3*time.Second, func() { closeConn(cli) })
	defer stop.Stop()
	for range seal.AuthBudget {
		if err := cli.SendDatagram(pkt); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case got := <-ch:
		if got.id != 7 || got.code != "auth" {
			t.Fatalf("%+v", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no report")
	}
}

func TestBridgePin(t *testing.T) {
	cert, roots, _ := testCert(t)
	b, ln, uc := serveBridge(t, cert, nil)
	tok := bytes.Repeat([]byte("T"), seal.TokenSize)
	exp := time.Duration(time.Now().Add(2 * time.Minute).UnixNano())
	if err := b.Admit(7, tok, 0, exp); err != nil {
		t.Fatal(err)
	}
	if err := b.Admit(9, tok, 0, exp); err != nil {
		t.Fatal(err)
	}
	agent, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := agent.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("agent: %v", err)
		}
	}()
	bridgeAddr := uc.LocalAddr().(*net.UDPAddr)
	good := pingPkt(7, tok)
	if _, err := agent.WriteToUDP(good, bridgeAddr); err != nil {
		t.Fatal(err)
	}
	tlsCli, err := ClientConfig("127.0.0.1", roots, nil)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	cli, err := Dial(dctx, ln.Addr().String(), tlsCli, DatagramConf())
	dcancel()
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn(cli)
	time.Sleep(50 * time.Millisecond)
	if err := cli.SendDatagram(good); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, frame.MaxDatagram)
	if err := agent.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := agent.ReadFromUDP(buf)
	if err != nil || n == 0 {
		t.Fatalf("n=%d %v", n, err)
	}

	dctx, dcancel = context.WithTimeout(context.Background(), 5*time.Second)
	cli2, err := Dial(dctx, ln.Addr().String(), tlsCli, DatagramConf())
	dcancel()
	if err != nil {
		t.Fatal(err)
	}
	defer closeConn(cli2)
	time.Sleep(50 * time.Millisecond)
	if err := cli2.SendDatagram(good); err != nil {
		t.Fatal(err)
	}
	if err := agent.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err = agent.ReadFromUDP(buf)
	ne, ok := err.(net.Error)
	if err == nil || !ok || !ne.Timeout() {
		t.Fatalf("%v", err)
	}

	other := pingPkt(9, tok)
	if err := cli.SendDatagram(other); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := agent.WriteToUDP(other, bridgeAddr); err != nil {
		t.Fatal(err)
	}
	if err := agent.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err = agent.ReadFromUDP(buf)
	ne, ok = err.(net.Error)
	if err == nil || !ok || !ne.Timeout() {
		t.Fatalf("%v", err)
	}
}

func TestBridgeAdmit(t *testing.T) {
	b := New()
	tok := bytes.Repeat([]byte("T"), seal.TokenSize)
	exp := time.Duration(time.Now().Add(time.Minute).UnixNano())
	if err := b.Admit(7, tok, 0, exp); err != nil {
		t.Fatal(err)
	}
	if err := b.Admit(7, tok, 0, exp); err == nil || err.Error() != "exists" {
		t.Fatalf("%v", err)
	}
	if err := b.Admit(7, tok[:15], 0, exp); err == nil || err.Error() != "bad_grant" {
		t.Fatalf("%v", err)
	}
	if err := b.Admit(0, tok, 0, exp); err == nil || err.Error() != "bad_grant" {
		t.Fatalf("%v", err)
	}
	var nb *Bridge
	if err := nb.Admit(1, tok, 0, exp); err == nil || err.Error() != "internal" {
		t.Fatalf("%v", err)
	}
	if err := nb.Serve(context.Background(), nil, nil, nil); err == nil || err.Error() != "internal" {
		t.Fatalf("%v", err)
	}
	if err := (&Bridge{}).Admit(1, tok, 0, exp); err == nil || err.Error() != "internal" {
		t.Fatalf("%v", err)
	}
	if err := (&Bridge{}).Serve(context.Background(), nil, nil, nil); err == nil || err.Error() != "internal" {
		t.Fatalf("%v", err)
	}

	cert, _, _ := testCert(t)
	ln, err := Listen("127.0.0.1:0", ServerConfig(cert), DatagramConf())
	if err != nil {
		t.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- New().Serve(ctx, ln, uc, nil) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve")
	}
	if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := uc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

func TestWriteUDPStuck(t *testing.T) {
	b := New()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.enqueueUDP("127.0.0.1:1", 7, []byte("x"))
	done := make(chan struct{})
	go func() {
		b.writeUDP(ctx, c)
		close(done)
	}()
	time.Sleep(20 * time.Millisecond)
	b.mu.Lock()
	n := len(b.udpq)
	b.mu.Unlock()
	if n != 1 {
		t.Fatalf("len=%d", n)
	}
	cancel()
	b.mu.Lock()
	b.cond.Broadcast()
	b.mu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stuck")
	}
}

func TestSourceGuards(t *testing.T) {
	names := []string{"quic.go", "datagram.go", "stream.go", "bridge.go"}
	for _, name := range names {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		if strings.Contains(s, "DialAddrEarly") || strings.Contains(s, "ListenAddrEarly") {
			t.Fatalf("%s early", name)
		}
		if strings.Contains(s, "InsecureSkipVerify: true") || strings.Contains(s, "InsecureSkipVerify = true") || strings.Contains(s, "InsecureSkipVerify=true") {
			t.Fatalf("%s skip", name)
		}
	}
	q, err := os.ReadFile("quic.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(q), "if cfg.InsecureSkipVerify") {
		t.Fatal("missing check")
	}
	br, err := os.ReadFile("bridge.go")
	if err != nil {
		t.Fatal(err)
	}
	bs := string(br)
	if strings.Contains(bs, "seal.New") || strings.Contains(bs, "sess.Open") || strings.Contains(bs, ".Key") {
		t.Fatal("bridge key")
	}
	st, err := os.ReadFile("stream.go")
	if err != nil {
		t.Fatal(err)
	}
	ss := string(st)
	if strings.Contains(ss, "internal/engine") || strings.Contains(ss, "engine.New") {
		t.Fatal("stream engine")
	}
}
