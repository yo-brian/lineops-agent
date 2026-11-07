package release

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

// PrivateNetwork trials cannot reach the production Reality handshake target.
// Use a TLS 1.3 fixture only inside that isolated namespace; the effective model
// on disk is unchanged and the post-restart probe uses the real target.
func trialRealityTarget(m *Model) (func(), error) {
	names := []string{}
	for _, n := range m.Nodes {
		if n.ProtocolOptions.Normalized().Security == "reality" {
			names = append(names, n.ServerName)
		}
	}
	if len(names) == 0 {
		return func() {}, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	tlsListener := tls.NewListener(ln, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"http/1.1"}})
	server := &http.Server{ErrorLog: log.New(io.Discard, "", 0), ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })}
	go func() { _ = server.Serve(tlsListener) }()
	for i := range m.Nodes {
		if m.Nodes[i].ProtocolOptions.Normalized().Security == "reality" {
			m.Nodes[i].RealityHandshake = "127.0.0.1"
			m.Nodes[i].RealityHandshakePort = port
		}
	}
	return func() { _ = server.Close(); _ = ln.Close() }, nil
}
