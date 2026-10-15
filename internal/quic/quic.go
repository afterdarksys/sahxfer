// Package quic is the QUIC pipe for one sahxfer grant.
//
// Threats: TLS older than 1.3, a skipped name check, a pin that is not
// 32 bytes, 0-RTT, and an ALPN other than sahxfer/1. Verification is not
// skipped. A pin failure is auth. This package does not log certificates,
// keys, or route tokens. QUIC does not authorize the grant.
package quic

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"

	qgo "github.com/quic-go/quic-go"

	"github.com/afterdarksys/sahxfer/internal/code"
)

// ALPN is the only application protocol this pipe accepts.
const ALPN = "sahxfer/1"

// ClientConfig is the dialer's TLS 1.3 config. A nil or empty pin uses
// ordinary chain and name checks. Any other length is auth, before a dial.
// The pin is copied. The caller may wipe its buffer after this returns.
func ClientConfig(serverName string, roots *x509.CertPool, pin []byte) (*tls.Config, error) {
	if len(pin) != 0 && len(pin) != 32 {
		return nil, code.New("auth")
	}
	var pinned []byte
	if len(pin) == 32 {
		pinned = append([]byte(nil), pin...)
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		NextProtos: []string{ALPN},
		ServerName: serverName,
		RootCAs:    roots,
	}
	if pinned != nil {
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 || verifiedChains[0][0] == nil {
				return code.New("auth")
			}
			sum := sha256.Sum256(verifiedChains[0][0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], pinned) != 1 {
				return code.New("auth")
			}
			return nil
		}
	}
	if err := checkTLS(cfg, false); err != nil {
		return nil, err
	}
	return cfg, nil
}

// ServerConfig presents one certificate and asks for none from the client.
func ServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{ALPN},
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.NoClientCert,
	}
}

// DatagramConf carries sealed frames and no streams.
func DatagramConf() *qgo.Config {
	return &qgo.Config{
		EnableDatagrams:       true,
		Allow0RTT:             false,
		Versions:              []qgo.Version{qgo.Version1},
		MaxIncomingStreams:    -1,
		MaxIncomingUniStreams: -1,
	}
}

// StreamConf carries the file and the hash. Datagrams stay off.
func StreamConf() *qgo.Config {
	return &qgo.Config{
		EnableDatagrams:       false,
		Allow0RTT:             false,
		Versions:              []qgo.Version{qgo.Version1},
		MaxIncomingStreams:    -1,
		MaxIncomingUniStreams: 4,
	}
}

// Dial checks the configs, then dials. A rejected config does not touch the network.
func Dial(ctx context.Context, addr string, tlsConf *tls.Config, conf *qgo.Config) (*qgo.Conn, error) {
	if err := checkTLS(tlsConf, false); err != nil {
		return nil, err
	}
	if err := checkQUIC(conf); err != nil {
		return nil, err
	}
	conn, err := qgo.DialAddr(ctx, addr, tlsConf, conf)
	if err != nil {
		return nil, mapDial(err)
	}
	return conn, nil
}

// Listen checks the configs, then listens.
func Listen(addr string, tlsConf *tls.Config, conf *qgo.Config) (*qgo.Listener, error) {
	if err := checkTLS(tlsConf, true); err != nil {
		return nil, err
	}
	if err := checkQUIC(conf); err != nil {
		return nil, err
	}
	ln, err := qgo.ListenAddr(addr, tlsConf, conf)
	if err != nil {
		return nil, mapDial(err)
	}
	return ln, nil
}

func checkTLS(cfg *tls.Config, server bool) error {
	if cfg == nil {
		return code.New("auth")
	}
	if cfg.InsecureSkipVerify {
		return code.New("auth")
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		return code.New("auth")
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != ALPN {
		return code.New("auth")
	}
	if server && (cfg.ClientAuth != tls.NoClientCert || len(cfg.Certificates) == 0) {
		return code.New("auth")
	}
	return nil
}

func checkQUIC(cfg *qgo.Config) error {
	if cfg == nil || cfg.Allow0RTT {
		return code.New("auth")
	}
	if len(cfg.Versions) != 1 || cfg.Versions[0] != qgo.Version1 {
		return code.New("auth")
	}
	return nil
}

// mapDial turns a library error into a code. Context errors pass through.
// A crypto or certificate failure is auth. A datagram that does not fit is protocol.
func mapDial(err error) error {
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
	var too *qgo.DatagramTooLargeError
	if errors.As(err, &too) {
		return code.New("protocol")
	}
	var hs *qgo.HandshakeTimeoutError
	if errors.As(err, &hs) {
		return code.New("io")
	}
	var ver *tls.CertificateVerificationError
	if errors.As(err, &ver) {
		return code.New("auth")
	}
	var ua x509.UnknownAuthorityError
	if errors.As(err, &ua) {
		return code.New("auth")
	}
	var hn x509.HostnameError
	if errors.As(err, &hn) {
		return code.New("auth")
	}
	var te *qgo.TransportError
	if errors.As(err, &te) && te.ErrorCode.IsCryptoError() {
		return code.New("auth")
	}
	var vn *qgo.VersionNegotiationError
	if errors.As(err, &vn) {
		return code.New("auth")
	}
	return code.New("io")
}
