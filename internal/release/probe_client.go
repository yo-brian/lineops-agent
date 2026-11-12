package release

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Every node must carry a fresh nonce through the real protocol implementation.
// A listening socket, a successful config check, or an exited client is not health.
// The runtime supplies its locally registered and hash-checked sing-box binary.
func probeWithClient(ctx context.Context, binary, dir string, m Model) error {
	if len(m.Nodes) == 0 {
		return nil
	}
	expanded := []Node{}
	for _, n := range m.Nodes {
		expanded = append(expanded, n.AuthenticationNodes()...)
	}
	m.Nodes = expanded
	if len(m.Nodes) > 1024 {
		return errors.New("too many probe nodes")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
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
	origin := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, expected) })}
	go func() { _ = origin.Serve(ln) }()
	defer origin.Close()
	work, err := os.MkdirTemp("", "lineops-protocol-probe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	inbounds, outbounds, rules := []any{}, []any{}, []any{}
	ports := make([]int, len(m.Nodes))
	reserved := []net.Listener{}
	defer func() {
		for _, l := range reserved {
			_ = l.Close()
		}
	}()
	for i, n := range m.Nodes {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			return e
		}
		reserved = append(reserved, l)
		ports[i] = l.Addr().(*net.TCPAddr).Port
		tag := fmt.Sprintf("probe-%d", i)
		host := n.Listen
		if host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		if host == "::" {
			host = "::1"
		}
		out := ClientOutbound(n, host)
		if n.RelayAddress != "" && n.RelayTrustPEM != "" {
			out["tls"].(map[string]any)["certificate"] = []string{n.RelayTrustPEM}
		}
		if n.UsesCertificate() {
			trust, e := readRegular(filepath.Join(dir, "trust-"+n.CertificateID+".pem"))
			if e != nil {
				return errors.New("probe trust unavailable")
			}
			out["tls"].(map[string]any)["certificate"] = []string{string(trust)}
		}
		inbounds = append(inbounds, map[string]any{"type": "mixed", "tag": tag, "listen": "127.0.0.1", "listen_port": ports[i]})
		outbounds = append(outbounds, out)
		rules = append(rules, map[string]any{"inbound": []string{tag}, "action": "route", "outbound": "node-" + n.ID})
	}
	data, err := json.Marshal(map[string]any{"log": map[string]bool{"disabled": true}, "inbounds": inbounds, "outbounds": outbounds, "route": map[string]any{"rules": rules}})
	if err != nil {
		return err
	}
	path := filepath.Join(work, "client.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	for _, l := range reserved {
		_ = l.Close()
	}
	cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
	cmd.Dir = work
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return errors.New("protocol probe client start failed")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { _ = cmd.Process.Kill(); <-done }()
	// Peek without consuming the single completion value needed by cleanup.
	alive := func() bool {
		select {
		case e := <-done:
			done <- e
			return false
		default:
			return true
		}
	}
	for i, n := range m.Nodes {
		if n.RelayAddress != "" && n.ProtocolOptions.Normalized().Encryption != "" {
			host := n.Listen
			if host == "0.0.0.0" {
				host = "127.0.0.1"
			}
			if host == "::" {
				host = "::1"
			}
			verified := false
			for ctx.Err() == nil && alive() {
				conn, e := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, n.Port))
				if e == nil {
					_ = conn.Close()
					if alive() {
						verified = true
						break
					}
				}
				select {
				case <-ctx.Done():
				case <-time.After(100 * time.Millisecond):
				}
			}
			if !verified {
				return fmt.Errorf("node %s: authenticated protocol/egress verification failed", n.ID)
			}
			continue
		}
		proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", ports[i]))
		transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		verified := false
		for ctx.Err() == nil && alive() {
			target := "http://" + ln.Addr().String() + "/"
			if n.RelayAddress != "" {
				target = "https://www.gstatic.com/generate_204?lineops=" + expected
			}
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			response, e := client.Do(request)
			if e == nil {
				body, e := io.ReadAll(io.LimitReader(response.Body, 1024))
				response.Body.Close()
				validResponse := response.StatusCode == 200 && string(body) == expected
				if n.RelayAddress != "" {
					validResponse = response.StatusCode == 204 && response.TLS != nil && len(response.TLS.VerifiedChains) > 0
				}
				if e == nil && validResponse && alive() {
					verified = true
					break
				}
			}
			select {
			case <-ctx.Done():
			case <-time.After(100 * time.Millisecond):
			}
		}
		transport.CloseIdleConnections()
		if !verified {
			return fmt.Errorf("node %s: authenticated protocol/egress verification failed", n.ID)
		}
	}
	return nil
}
