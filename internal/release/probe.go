package release

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// Probe speaks an authenticated VLESS TCP request over verified TLS and checks
// the bytes returned by a loopback-only controlled origin through direct egress.
// It does not accept arbitrary URLs, hostnames or metadata-network targets.
func Probe(ctx context.Context, dir string, m Model, binaryPaths ...string) error {
	if len(binaryPaths) > 0 && binaryPaths[0] != "" {
		return probeWithClient(ctx, binaryPaths[0], dir, m)
	}
	if ModelTemplate(m.Nodes) != Template {
		return errors.New("multi-protocol probe requires registered sing-box binary")
	}
	if len(m.Nodes) == 0 {
		return nil
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	nonce := make([]byte, 24)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	expected := hex.EncodeToString(nonce)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, expected)
	}), ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(ln) }()
	defer server.Close()
	targetPort := uint16(ln.Addr().(*net.TCPAddr).Port)
	for _, n := range m.Nodes {
		roots := x509.NewCertPool()
		trust, e := readRegular(filepath.Join(dir, "trust-"+n.CertificateID+".pem"))
		if e != nil || !roots.AppendCertsFromPEM(trust) {
			return errors.New("probe trust unavailable")
		}
		host := n.Listen
		if host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		if host == "::" {
			host = "::1"
		}
		d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: n.ServerName, RootCAs: roots}}
		var conn net.Conn
		deadline := time.Now().Add(8 * time.Second)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		for time.Now().Before(deadline) {
			conn, e = d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(n.Port))))
			if e == nil {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if e != nil {
			return errors.New("TLS listener or handshake failed")
		}
		e = func() error {
			defer conn.Close()
			_ = conn.SetDeadline(deadline)
			id, x := DecodeUUID(n.UUID)
			if x != nil {
				return x
			}
			header := []byte{0}
			header = append(header, id...)
			header = append(header, 0, 1)
			header = binary.BigEndian.AppendUint16(header, targetPort)
			header = append(header, 1, 127, 0, 0, 1)
			header = append(header, []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")...)
			if _, x = conn.Write(header); x != nil {
				return errors.New("VLESS request failed")
			}
			response := make([]byte, 2)
			if _, x = io.ReadFull(conn, response); x != nil || response[0] != 0 {
				return errors.New("VLESS authentication failed")
			}
			if _, x = io.CopyN(io.Discard, conn, int64(response[1])); x != nil {
				return x
			}
			httpResponse, x := http.ReadResponse(bufio.NewReader(conn), nil)
			if x != nil {
				return errors.New("direct outbound response missing")
			}
			defer httpResponse.Body.Close()
			body, x := io.ReadAll(io.LimitReader(httpResponse.Body, 1024))
			if x != nil || httpResponse.StatusCode != 200 || string(body) != expected {
				return errors.New("direct outbound verification failed")
			}
			return nil
		}()
		if e != nil {
			return fmt.Errorf("node %s: %w", n.ID, e)
		}
	}
	return nil
}

// TrialLocal must only be entered in the private network namespace created by
// SystemdRuntime.Trial. It refuses the host's network namespace even when called
// directly, so trial listeners can never seize a production port.
func TrialLocal(ctx context.Context, binaryPath, versionDir, hostNetwork string) error {
	isolated, err := isolatedNetwork(hostNetwork)
	if err != nil || !isolated {
		return errors.New("trial requires isolated network namespace")
	}
	var m Model
	if err = readJSON(filepath.Join(versionDir, "model.json"), &m); err != nil {
		return err
	}
	certs, err := CertificatesFromDir(versionDir, m)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "lineops-trial-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for i := range m.Nodes {
		m.Nodes[i].Listen = "127.0.0.1"
		m.Nodes[i].Port = uint16(20000 + i)
	}
	stopRelays, err := trialRelayTargets(&m)
	if err != nil {
		return err
	}
	defer stopRelays()
	stopReality, err := trialRealityTarget(&m)
	if err != nil {
		return err
	}
	defer stopReality()
	for _, c := range certs {
		for name, b := range map[string][]byte{"tls-" + c.ID + ".pem": c.CertificatePEM, "key-" + c.ID + ".pem": c.PrivateKeyPEM, "trust-" + c.ID + ".pem": c.TrustPEM} {
			if err = os.WriteFile(filepath.Join(dir, name), b, 0600); err != nil {
				return err
			}
		}
	}
	config, err := Render(m, dir)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "config.json"), config, 0600); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, binaryPath, "run", "-c", filepath.Join(dir, "config.json"))
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return errors.New("trial start failed")
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if err = probeTrialRelays(ctx, m); err != nil {
		return err
	}
	direct := m
	direct.Nodes = nil
	for _, n := range m.Nodes {
		if n.RelayAddress == "" {
			direct.Nodes = append(direct.Nodes, n)
		}
	}
	direct.Template = ModelTemplate(direct.Nodes)
	if err = Probe(ctx, dir, direct, binaryPath); err != nil {
		return err
	}
	if len(m.Nodes) == 0 {
		time.Sleep(300 * time.Millisecond)
	}
	if !processAlive(cmd.Process) {
		return errors.New("trial process exited")
	}
	return nil
}
func readModel(dir string) (Model, error) {
	var m Model
	err := readJSON(filepath.Join(dir, "model.json"), &m)
	return m, err
}
func ReadRequest(path string) (Request, error) {
	var r Request
	err := readJSON(path, &r)
	return r, err
}
func ReadPolicies(path string) (PolicySet, error) {
	var r PolicySet
	err := readJSON(path, &r)
	return r, err
}
func ReadRuntime(path string) (RuntimeConfig, error) {
	var r RuntimeConfig
	err := readJSON(path, &r)
	return r, err
}
func ProbeVersion(ctx context.Context, dir string, binary ...string) error {
	m, err := readModel(dir)
	if err != nil {
		return err
	}
	return Probe(ctx, dir, m, binary...)
}
func outputHasVersion(b []byte, v string) bool {
	return bytes.Contains(b, []byte("sing-box version "+v+"\n"))
}
