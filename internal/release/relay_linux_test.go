//go:build linux

package release

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Real sing-box entry and landing processes on isolated loopback ports. Uses
// test-only loopback destinations; production validation rejects these IPs.
func TestRealTCPRelayClients(t *testing.T) {
	binary := os.Getenv("LINEOPS_TEST_SINGBOX")
	if binary == "" {
		t.Skip("LINEOPS_TEST_SINGBOX required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	dir := t.TempDir()
	cert := testCertificate(t)
	for name, data := range map[string][]byte{"tls-" + cert.ID + ".pem": cert.CertificatePEM, "key-" + cert.ID + ".pem": cert.PrivateKeyPEM, "trust-" + cert.ID + ".pem": cert.TrustPEM} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	landing := Model{Schema: 1, Template: MultiProtocolTemplate}
	entry := Model{Schema: 1, Template: TCPRelayTemplate}
	reservations := []net.Listener{}
	defer func() {
		for _, l := range reservations {
			_ = l.Close()
		}
	}()
	port := func() uint16 {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, l)
		return uint16(l.Addr().(*net.TCPAddr).Port)
	}
	for i, options := range protocolMatrix() {
		n := Node{ProtocolOptions: options, ID: fmt.Sprintf("relay-%d", i), GroupID: "group", CredentialID: fmt.Sprintf("credential-%d", i), Listen: "127.0.0.1", Port: port(), ServerName: "lineops-test.invalid"}
		if n.Protocol == "vless" || n.Protocol == "vmess" {
			n.UUID = fmt.Sprintf("11111111-1111-4111-8111-%012d", i)
		} else {
			var err error
			n.Password, err = options.NewPassword()
			if err != nil {
				t.Fatal(err)
			}
		}
		if n.Security == "tls" {
			n.CertificateID = cert.ID
		}
		if n.Security == "none" {
			n.ServerName = ""
		}
		if n.Security == "reality" {
			var err error
			n.RealityPrivateKey, n.RealityPublicKey, n.RealityShortID, err = NewRealityKey()
			if err != nil {
				t.Fatal(err)
			}
		}
		landing.Nodes = append(landing.Nodes, n)
	}
	stop, err := trialRealityTarget(&landing)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	for _, n := range landing.Nodes {
		n.RelayAddress = "127.0.0.1"
		n.RelayPort = n.Port
		n.Port = port()
		n.CertificateID = ""
		n.RealityPrivateKey = ""
		entry.Nodes = append(entry.Nodes, n)
	}
	for _, l := range reservations {
		_ = l.Close()
	}
	start := func(name string, m Model) {
		t.Helper()
		data, err := Render(m, dir)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, name+".json")
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.CommandContext(ctx, binary, "check", "-c", path).CombinedOutput(); err != nil {
			t.Fatalf("%s check failed: %v %s", name, err, output)
		}
		cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	}
	start("landing", landing)
	start("entry", entry)
	testRealSubscriptionClients(t, ctx, dir, binary, entry, cert)
}

func TestRealTCPRelayIsolatedTrial(t *testing.T) {
	binary := os.Getenv("LINEOPS_TEST_SINGBOX")
	recovery := os.Getenv("LINEOPS_TEST_RECOVERY")
	if binary == "" || recovery == "" || os.Geteuid() != 0 {
		t.Skip("explicit Linux test binaries and root required")
	}
	dir, err := os.MkdirTemp("/var/lib", "lineops-relay-trial-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	n := relayFixture()
	m := Model{Schema: 1, Template: TCPRelayTemplate, Nodes: []Node{n}}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "model.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err = (SystemdRuntime{}).Trial(ctx, RuntimeConfig{ServiceUser: "root", RecoveryBinary: recovery, Binary: binary}, dir); err != nil {
		t.Fatal(err)
	}
}
