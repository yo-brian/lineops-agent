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

func TestRealMultiProtocolClients(t *testing.T) {
	binary := os.Getenv("LINEOPS_TEST_SINGBOX")
	if binary == "" {
		t.Skip("LINEOPS_TEST_SINGBOX required for real protocol acceptance")
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
	m := Model{Schema: 1, Template: MultiProtocolTemplate}
	var reservations []net.Listener
	defer func() {
		for _, l := range reservations {
			_ = l.Close()
		}
	}()
	for i, options := range protocolMatrix() {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		reservations = append(reservations, l)
		n := Node{ProtocolOptions: options, ID: fmt.Sprintf("node-%d", i), GroupID: "group", CredentialID: fmt.Sprintf("credential-%d", i), Listen: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port), ServerName: "lineops-test.invalid"}
		if n.Protocol == "vless" || n.Protocol == "vmess" {
			n.UUID = fmt.Sprintf("11111111-1111-4111-8111-%012d", i)
		} else {
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
			n.RealityPrivateKey, n.RealityPublicKey, n.RealityShortID, err = NewRealityKey()
			if err != nil {
				t.Fatal(err)
			}
		}
		m.Nodes = append(m.Nodes, n)
	}
	stop, err := trialRealityTarget(&m)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err = ValidateModel(m, []Certificate{cert}, time.Now()); err != nil {
		t.Fatal(err)
	}
	data, err := Render(m, dir)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.json")
	if err = os.WriteFile(config, data, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(ctx, binary, "check", "-c", config).CombinedOutput(); err != nil {
		t.Fatalf("server config rejected: %v %s", err, out)
	}
	for _, l := range reservations {
		_ = l.Close()
	}
	process := exec.CommandContext(ctx, binary, "run", "-c", config)
	if err = process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = process.Process.Kill(); _ = process.Wait() }()
	if err = Probe(ctx, dir, m, binary); err != nil {
		t.Fatal("full real protocol probe:", err)
	}
	// The actual subscription renderers are consumed by both real clients.
	testRealSubscriptionClients(t, ctx, dir, binary, m, cert)
	for _, index := range []int{0, 3, 6, 10, 12} {
		n := m.Nodes[index]
		if n.Security == "reality" {
			_, n.RealityPublicKey, _, err = NewRealityKey()
			if err != nil {
				t.Fatal(err)
			}
		} else if n.UUID != "" {
			n.UUID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
		} else {
			n.Password = "wrong-password-for-negative-fixture"
		}
		negativeCtx, negativeCancel := context.WithTimeout(ctx, 2*time.Second)
		err = Probe(negativeCtx, dir, Model{Nodes: []Node{n}}, binary)
		negativeCancel()
		if err == nil {
			t.Fatalf("invalid %s credentials accepted", n.Protocol)
		}
	}
	for _, n := range m.Nodes {
		t.Logf("verified %s / %s / %s / %s / %s", n.Protocol, n.Security, n.Transport, n.Flow, n.Method)
	}
	// Request model remains serializable and contains no arbitrary input blobs.
	if _, err = json.Marshal(m); err != nil {
		t.Fatal(err)
	}
}

func TestRealMultiProtocolSystemdPublication(t *testing.T) {
	binary, helper := os.Getenv("LINEOPS_TEST_SINGBOX"), os.Getenv("LINEOPS_TEST_RECOVERY")
	if binary == "" || helper == "" {
		t.Skip("explicit isolated sing-box/recovery paths required")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated systemd test requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	base, err := os.MkdirTemp("/var/lib", "lineops-protocol-acceptance-")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(base, 0755); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(base, "instances")
	id := fmt.Sprintf("proto-%d", time.Now().UnixNano())
	bytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	r := RuntimeConfig{InstanceID: id, Epoch: "protocol-epoch", Binary: binary, BinarySHA256: digest(bytes), BinaryVersion: "1.14.0", RecoveryBinary: helper, ServiceUser: "lineops-release-test"}
	defer func() {
		_ = command(context.Background(), "/usr/bin/systemctl", "stop", "lineops-policy-"+id+".timer", "lineops-policy-"+id+".service", "lineops-recover-"+id+"-*.timer", unit(r))
		_ = command(context.Background(), "/usr/bin/systemctl", "disable", "lineops-policy-"+id+".timer")
		for _, name := range []string{"lineops-policy-" + id + ".timer", "lineops-policy-" + id + ".service", unit(r)} {
			_ = os.Remove(filepath.Join("/etc/systemd/system", name))
		}
		_ = command(context.Background(), "/usr/bin/systemctl", "daemon-reload")
		_ = os.RemoveAll(base)
	}()
	if err = Initialize(ctx, root, r); err != nil {
		t.Fatal(err)
	}
	cert := testCertificate(t)
	m := Model{Schema: 1, Template: MultiProtocolTemplate}
	for i, index := range []int{1, 5, 7, 11, 15} {
		o := protocolMatrix()[index]
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := uint16(listener.Addr().(*net.TCPAddr).Port)
		listener.Close()
		n := Node{ProtocolOptions: o, ID: fmt.Sprintf("node-%d", i), GroupID: "group", CredentialID: fmt.Sprintf("credential-%d", i), Listen: "127.0.0.1", Port: port, ServerName: "lineops-test.invalid"}
		if n.Protocol == "vless" || n.Protocol == "vmess" {
			n.UUID = fmt.Sprintf("22222222-2222-4222-8222-%012d", i)
		} else {
			n.Password, err = o.NewPassword()
			if err != nil {
				t.Fatal(err)
			}
		}
		if n.UsesCertificate() {
			n.CertificateID = cert.ID
		}
		if n.Security == "none" {
			n.ServerName = ""
		}
		if n.Security == "reality" {
			n.RealityPrivateKey, n.RealityPublicKey, n.RealityShortID, err = NewRealityKey()
			if err != nil {
				t.Fatal(err)
			}
		}
		m.Nodes = append(m.Nodes, n)
	}
	stop, err := trialRealityTarget(&m)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	policies := PolicySet{Epoch: r.Epoch, Groups: map[string]GroupPolicy{"group": {Version: 1, ExpiresAt: time.Now().Add(time.Hour)}}}
	request := Request{TaskID: "protocol-create", Epoch: r.Epoch, InstanceID: id, Generation: 1, Fencing: 1, TargetGroups: []string{"group"}, Model: m, Certificates: []Certificate{cert}, Policies: policies, RecoverySeconds: 30}
	engine := Engine{Root: root, Runtime: SystemdRuntime{}}
	state, err := engine.Apply(ctx, request)
	if err != nil {
		t.Fatal("mixed protocol systemd publication", err, state)
	}
	if _, err = engine.VerifyStatus(ctx, id); err != nil {
		t.Fatal("fresh mixed protocol status", err)
	}
	bad := request
	bad.TaskID = "protocol-bind-failure"
	bad.Generation = 2
	bad.Fencing = 2
	bad.Model.Nodes = append([]Node{}, m.Nodes...)
	bad.Model.Nodes[0].Listen = "192.0.2.123"
	state, err = engine.Apply(ctx, bad)
	if err == nil || state.LastResult != "failed_rolled_back" {
		t.Fatal("mixed protocol rollback not verified", err, state)
	}
	if _, err = engine.VerifyStatus(ctx, id); err != nil {
		t.Fatal("rollback protocols not healthy", err)
	}
	next := PolicySet{Epoch: r.Epoch, Groups: map[string]GroupPolicy{"group": {Version: 2, ExpiresAt: time.Now().Add(-time.Second)}}}
	if _, err = engine.UpdatePolicies(ctx, id, next); err != nil {
		t.Fatal("mixed protocol expiry", err)
	}
	state, err = engine.Status(id)
	if err != nil {
		t.Fatal(err)
	}
	model, err := readModel(filepath.Join(root, id, "versions", state.CurrentVersion))
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 0 {
		t.Fatal("expired protocol credentials survived policy reconciliation")
	}
	t.Log("systemd isolated trial, five mixed protocol inbounds, live verification, failed-bind rollback and expiry all passed")
}
