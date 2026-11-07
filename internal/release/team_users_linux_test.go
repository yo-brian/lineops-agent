//go:build linux

package release

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// No systemd or production service is touched: these are temporary loopback
// servers and real clients. Verify credentials, user counters, and rejection
// after revocation against the same stats-enabled core used by the executor.
func TestRealTeamCredentialsAndTraffic(t *testing.T) {
	binary := os.Getenv("LINEOPS_SINGBOX_STATS_BINARY")
	if binary == "" {
		t.Skip("stats-enabled core required")
	}
	for _, protocol := range []string{"vless", "vmess", "trojan", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			dir := t.TempDir()
			cert := testCertificate(t)
			for name, b := range map[string][]byte{"tls-" + cert.ID + ".pem": cert.CertificatePEM, "key-" + cert.ID + ".pem": cert.PrivateKeyPEM, "trust-" + cert.ID + ".pem": cert.TrustPEM} {
				if e := os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			l, e := net.Listen("tcp4", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			port := uint16(l.Addr().(*net.TCPAddr).Port)
			l.Close()
			id := "aaaaaaaa-1111-4111-8111-111111111111"
			n := Node{ID: id, GroupID: "team", CredentialID: "legacy", Listen: "127.0.0.1", Port: port, CertificateID: cert.ID, ServerName: "lineops-test.invalid", UUID: "11111111-1111-4111-8111-111111111111", ProtocolOptions: ProtocolOptions{Protocol: protocol, Security: "tls", Transport: "tcp"}, Users: []UserCredential{{ID: "alice", UUID: "22222222-2222-4222-8222-222222222222"}, {ID: "shared", UUID: "33333333-3333-4333-8333-333333333333"}}}
			if protocol == "trojan" {
				n.UUID = ""
				n.Password = "legacy-long-random-password"
				for i := range n.Users {
					n.Users[i].UUID = ""
					n.Users[i].Password = fmt.Sprintf("user-%d-long-random-password", i)
				}
			}
			if strings.Contains(protocol, "gcm") || protocol == "chacha20-ietf-poly1305" {
				n.ProtocolOptions = ProtocolOptions{Protocol: "shadowsocks", Method: protocol, Security: "none", Transport: "tcp"}
				n.UUID, n.CertificateID, n.ServerName = "", "", ""
				n.SSMultiUser = true
				n.Password, e = n.ProtocolOptions.NewPassword()
				if e != nil {
					t.Fatal(e)
				}
				for i := range n.Users {
					n.Users[i].UUID = ""
					n.Users[i].Password, e = n.ProtocolOptions.NewPassword()
					if e != nil {
						t.Fatal(e)
					}
				}
			}
			m := Model{Schema: 1, Template: ModelTemplate([]Node{n}), Nodes: []Node{n}}
			if e = ValidateModel(m, []Certificate{cert}, time.Now()); e != nil {
				t.Fatal(e)
			}
			var cmd *exec.Cmd
			stop := func() {
				if cmd != nil {
					cmd.Process.Kill()
					cmd.Wait()
					cmd = nil
				}
			}
			defer stop()
			start := func(model Model) {
				t.Helper()
				raw, e := Render(model, dir)
				if e != nil {
					t.Fatal(e)
				}
				raw, e = addTrafficAPI(raw, id, model)
				if e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(dir, "server.json")
				if e = os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
				cmd = exec.CommandContext(ctx, binary, "run", "-c", path)
				if e = cmd.Start(); e != nil {
					t.Fatal(e)
				}
			}
			start(m)
			if e = Probe(ctx, dir, m, binary); e != nil {
				t.Fatal("independent authentication failed", e)
			}
			statsListener := trafficListener(id, m)
			endpoint := net.JoinHostPort(statsListener.Listen, strconv.Itoa(int(statsListener.Port)))
			counters, e := querySingboxTraffic(ctx, endpoint)
			if e != nil {
				t.Fatal(e)
			}
			for _, u := range n.Users {
				if counters["user>>>credential-"+u.ID+">>>traffic>>>uplink"] == 0 || counters["user>>>credential-"+u.ID+">>>traffic>>>downlink"] == 0 {
					t.Fatal("real per-user counters missing", counters)
				}
			}
			policy := PolicySet{Epoch: "epoch", Groups: map[string]GroupPolicy{"team": {Version: 2, ExpiresAt: time.Now().Add(time.Hour), RevokedCredentialIDs: []string{"alice"}, LegacyCredentialsDisabled: true}}}
			next, e := policy.Effective(m, time.Now())
			if e != nil {
				t.Fatal(e)
			}
			stop()
			start(next)
			if e = Probe(ctx, dir, next, binary); e != nil {
				t.Fatal("unrevoked shared identity stopped working", e)
			}
			old := n.AuthenticationNodes()[1]
			old.ID = n.ID
			rejected, cancelReject := context.WithTimeout(ctx, 2*time.Second)
			defer cancelReject()
			if e = Probe(rejected, dir, Model{Nodes: []Node{old}}, binary); e == nil {
				t.Fatal("revoked credential still authenticates")
			}
		})
	}
}
