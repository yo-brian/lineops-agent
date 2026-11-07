//go:build linux

package release

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// These are the same complete client shapes emitted by the subscription API.
// Only the mixed-port changes to avoid colliding with a developer's own proxy,
// and a per-process trusted test CA replaces the production system trust store.
func testRealSubscriptionClients(t *testing.T, ctx context.Context, base, singbox string, m Model, cert Certificate) {
	t.Helper()
	mihomo := os.Getenv("LINEOPS_TEST_MIHOMO")
	if mihomo == "" {
		t.Log("T26 Mihomo not executed: LINEOPS_TEST_MIHOMO absent")
	}
	ca := filepath.Join(base, "client-test-ca.pem")
	if err := os.WriteFile(ca, cert.TrustPEM, 0600); err != nil {
		t.Fatal(err)
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	marker := "lineops-controlled-client-response"
	server := http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, marker) })}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	for _, client := range []string{"sing-box", "mihomo"} {
		if client == "mihomo" && mihomo == "" {
			continue
		}
		for _, node := range m.Nodes {
			func() {
				dir, e := os.MkdirTemp(base, "client-")
				if e != nil {
					t.Fatal(e)
				}
				defer os.RemoveAll(dir)
				portListener, e := net.Listen("tcp4", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				port := portListener.Addr().(*net.TCPAddr).Port
				portListener.Close()
				tag := "node-" + node.ID
				var configuration any
				binary := singbox
				var checkArgs, runArgs []string
				if client == "sing-box" {
					configuration = map[string]any{"inbounds": []any{map[string]any{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{ClientOutbound(node, "127.0.0.1"), map[string]any{"type": "selector", "tag": "proxy", "outbounds": []string{tag}, "default": tag}}, "route": map[string]string{"final": "proxy"}}
					checkArgs = []string{"check", "-c", filepath.Join(dir, "client.json")}
					runArgs = []string{"run", "-c", filepath.Join(dir, "client.json")}
				} else {
					binary = mihomo
					configuration = map[string]any{"mixed-port": port, "allow-lan": false, "mode": "rule", "proxies": []any{MihomoProxy(node, "127.0.0.1")}, "proxy-groups": []any{map[string]any{"name": "proxy", "type": "select", "proxies": []string{tag}}}, "rules": []string{"MATCH,proxy"}}
					checkArgs = []string{"-t", "-f", filepath.Join(dir, "client.json"), "-d", dir}
					runArgs = []string{"-f", filepath.Join(dir, "client.json"), "-d", dir}
				}
				data, e := json.Marshal(configuration)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(dir, "client.json"), data, 0600); e != nil {
					t.Fatal(e)
				}
				check := exec.CommandContext(ctx, binary, checkArgs...)
				check.Dir = dir
				check.Env = append(os.Environ(), "SSL_CERT_FILE="+ca)
				check.Stdout = io.Discard
				check.Stderr = io.Discard
				if e = check.Run(); e != nil {
					t.Fatalf("%s parser rejected subscription shape: %v", client, e)
				}
				process := exec.CommandContext(ctx, binary, runArgs...)
				process.Dir = dir
				process.Env = check.Env
				process.Stdout = io.Discard
				process.Stderr = io.Discard
				if e = process.Start(); e != nil {
					t.Fatal(e)
				}
				defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
				proxy, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
				transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
				defer transport.CloseIdleConnections()
				httpClient := http.Client{Transport: transport, Timeout: 2 * time.Second}
				worked := false
				for until := time.Now().Add(8 * time.Second); time.Now().Before(until); {
					response, x := httpClient.Get("http://" + listener.Addr().String() + "/")
					if x == nil {
						b, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
						response.Body.Close()
						if response.StatusCode == 200 && string(b) == marker {
							worked = true
							break
						}
					}
					time.Sleep(100 * time.Millisecond)
				}
				if !worked {
					t.Fatalf("%s subscription parsed but failed verified TLS/proxy connection through %s", client, node.ID)
				}
				t.Logf("T26: %s parsed complete subscription and authenticated %s with trusted test CA", client, node.ID)
			}()
		}
	}
}
