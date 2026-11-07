//go:build linux

package release

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCertificate(t *testing.T) Certificate {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "Lineops isolated test CA"}, DNSNames: []string{"lineops-test.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return Certificate{ID: "test-ca", CertificatePEM: cert, PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), TrustPEM: cert}
}
func TestRealLinuxSharedReleaseAndIndependentRecovery(t *testing.T) {
	binaryPath := os.Getenv("LINEOPS_TEST_SINGBOX")
	helperPath := os.Getenv("LINEOPS_TEST_RECOVERY")
	if binaryPath == "" || helperPath == "" {
		t.Skip("set real sing-box and recovery binary paths in isolated root Linux")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated systemd integration requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	base, e := os.MkdirTemp("/var/lib", "lineops-release-acceptance-")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(base, 0755); e != nil {
		t.Fatal(e)
	}
	id := fmt.Sprintf("test-%d", time.Now().UnixNano())
	root := filepath.Join(base, "instances")
	binaryBytes, e := os.ReadFile(binaryPath)
	if e != nil {
		t.Fatal(e)
	}
	serviceUser := os.Getenv("LINEOPS_TEST_SERVICE_USER")
	if serviceUser == "" {
		serviceUser = "lineops-release-test"
	}
	r := RuntimeConfig{InstanceID: id, Epoch: "isolated-epoch", Binary: binaryPath, BinarySHA256: digest(binaryBytes), BinaryVersion: "1.14.0", RecoveryBinary: helperPath, ServiceUser: serviceUser}
	defer func() {
		_ = command(context.Background(), "/usr/bin/systemctl", "stop", "lineops-policy-"+id+".timer", "lineops-policy-"+id+".service")
		_ = command(context.Background(), "/usr/bin/systemctl", "disable", "lineops-policy-"+id+".timer")
		_ = os.Remove(filepath.Join("/etc/systemd/system", "lineops-policy-"+id+".timer"))
		_ = os.Remove(filepath.Join("/etc/systemd/system", "lineops-policy-"+id+".service"))
		_ = command(context.Background(), "/usr/bin/systemctl", "stop", "lineops-recover-"+id+"-*.timer")
		_ = command(context.Background(), "/usr/bin/systemctl", "stop", unit(r))
		_ = command(context.Background(), "/usr/bin/systemctl", "disable", unit(r))
		_ = os.Remove(filepath.Join("/etc/systemd/system", unit(r)))
		_ = command(context.Background(), "/usr/bin/systemctl", "daemon-reload")
		if strings.HasPrefix(base, "/var/lib/lineops-release-acceptance-") {
			_ = os.RemoveAll(base)
		}
	}()
	if e = Initialize(ctx, root, r); e != nil {
		t.Fatal("initialize:", e)
	}
	engine := Engine{Root: root, Runtime: SystemdRuntime{}}
	cert := testCertificate(t)
	a := Node{ID: "node-a", GroupID: "group-a", CredentialID: "cred-a1", UUID: "11111111-1111-4111-8111-111111111111", Listen: "127.0.0.1", Port: 24501, ServerName: "lineops-test.invalid", CertificateID: cert.ID}
	b := a
	b.ID = "node-b"
	b.GroupID = "group-b"
	b.CredentialID = "cred-b1"
	b.UUID = "22222222-2222-4222-8222-222222222222"
	b.Port = 24502
	p := PolicySet{Epoch: r.Epoch, Groups: map[string]GroupPolicy{"group-a": {Version: 1, ExpiresAt: time.Now().Add(time.Hour)}, "group-b": {Version: 1, ExpiresAt: time.Now().Add(time.Hour)}}}
	req := Request{TaskID: "create-a-b", Epoch: r.Epoch, InstanceID: id, Generation: 1, Fencing: 1, TargetGroups: []string{"group-a", "group-b"}, Model: Model{Schema: 1, Template: Template, Nodes: []Node{a, b}}, Certificates: []Certificate{cert}, Policies: p, RecoverySeconds: 15}
	s, e := engine.Apply(ctx, req)
	if e != nil {
		t.Log("preflight detail:", (SystemdRuntime{}).Check(ctx, r, filepath.Join(root, id, "versions", "v-1-1")))
		t.Fatal("initial real A/B release:", e)
	}
	if s.LastResult != "succeeded" {
		t.Fatal(s.LastResult)
	}
	if err := command(ctx, "/usr/bin/systemctl", "is-enabled", "--quiet", unit(r)); err != nil {
		t.Fatal("published service must start on host boot:", err)
	}
	t.Log("T08: real sing-box 1.14.0 A/B VLESS+TLS handshake + direct response succeeded")
	testRealSubscriptionClients(t, ctx, base, binaryPath, req.Model, cert)
	bad := req
	bad.TaskID = "preflight-cross-group-rejected"
	bad.Generation = 2
	bad.Fencing = 2
	bad.TargetGroups = []string{"group-a"}
	bad.Model.Nodes = append([]Node{}, req.Model.Nodes...)
	bad.Model.Nodes[1].Port++
	rejected, err := engine.Apply(ctx, bad)
	if err == nil || rejected.LastTaskID != bad.TaskID || rejected.LastResult != "failed_manual" || rejected.ErrorCode != "preflight_rejected" {
		t.Fatal("preflight failure lacked durable explicit task evidence")
	}
	record, x := engine.Receipt(id, bad.TaskID)
	if x != nil || record.RequestDigest == "" || record.Generation != 2 {
		t.Fatal("preflight receipt missing")
	}
	unchanged, x := engine.Status(id)
	if x != nil || unchanged.Generation != 1 || unchanged.CurrentVersion != s.CurrentVersion {
		t.Fatal("preflight rejection changed live high-water mark")
	}
	t.Log("T11/T17: cross-group preflight rejected with immutable receipt and unchanged live state")
	req.TaskID = "rotate-a"
	req.Generation = 2
	req.Fencing = 2
	req.TargetGroups = []string{"group-a"}
	req.Model.Nodes[0].CredentialID = "cred-a2"
	req.Model.Nodes[0].UUID = "33333333-3333-4333-8333-333333333333"
	s, e = engine.Apply(ctx, req)
	if e != nil {
		t.Fatal("A rotation:", e)
	}
	dir := filepath.Join(root, id, "versions", s.CurrentVersion)
	if e = Probe(ctx, dir, Model{Nodes: []Node{a}}); e == nil {
		t.Fatal("old A cached credential still valid")
	}
	if e = Probe(ctx, dir, Model{Nodes: []Node{b}}); e != nil {
		t.Fatal("B changed:", e)
	}
	t.Log("T25/T08: old A credential rejected, B remains authenticated after restart")
	// The candidate passes check and namespace trial, but its formal listen
	// address is deliberately absent on this isolated Linux machine.
	req.TaskID = "formal-start-failure"
	req.Generation = 3
	req.Fencing = 3
	req.Model.Nodes[0].Listen = "192.0.2.99"
	s, e = engine.Apply(ctx, req)
	if e == nil || s.LastResult != "failed_rolled_back" {
		t.Fatalf("formal failure was not safely restored: %s %v", s.LastResult, e)
	}
	if e = Probe(ctx, filepath.Join(root, id, "versions", s.CurrentVersion), Model{Nodes: []Node{b}}); e != nil {
		t.Fatal("recovered B", e)
	}
	t.Log("T12: actual formal bind failure restored known version; business result failed_rolled_back")
	// Stale independent timer must not rewrite a confirmed later publication.
	req.TaskID = "after-recovery"
	req.Generation = 4
	req.Fencing = 4
	req.Model.Nodes[0].Listen = "127.0.0.1"
	s, e = engine.Apply(ctx, req)
	if e != nil {
		t.Fatal(e)
	}
	version := s.CurrentVersion
	late, e := engine.Recover(ctx, id, "formal-start-failure", 3, true)
	if e != nil || late.CurrentVersion != version {
		t.Fatal("late timer changed newer version")
	}
	t.Log("T15: stale recovery guard ignored")
	// Independent process is killed after the durable journal and actual switch.
	req.TaskID = "killed-publisher"
	req.Generation = 5
	req.Fencing = 5
	req.Model.Nodes[0].Listen = "192.0.2.99"
	input := filepath.Join(base, "request.json")
	if e = writeJSON(input, req); e != nil {
		t.Fatal(e)
	}
	child := exec.Command(helperPath, "apply", "--root", root, "--input", input)
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	switched := false
	for until := time.Now().Add(20 * time.Second); time.Now().Before(until); {
		j, x := activeJournal(filepath.Join(root, id))
		if x == nil && j.TaskID == req.TaskID && j.State == "switched" {
			switched = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !switched {
		_ = child.Process.Kill()
		_ = child.Wait()
		t.Fatal("publisher never reached switched journal")
	}
	_ = child.Process.Kill()
	_ = child.Wait()
	// A newer policy arrives while the independent recovery is pending. The old
	// verified snapshot still contains A, but recovery must remove its credential.
	p.Groups["group-a"] = GroupPolicy{Version: 2, ExpiresAt: time.Now().Add(-time.Second)}
	if e = writeJSON(filepath.Join(root, id, "policies.json"), p); e != nil {
		t.Fatal(e)
	}
	if e = engine.StartGate(id); e == nil {
		t.Fatal("boot/start gate accepted stale authorization")
	}
	// No call to Engine.Recover here: the independently armed systemd timer must
	// execute the standalone binary while the publisher no longer exists.
	recovered := false
	for until := time.Now().Add(40 * time.Second); time.Now().Before(until); {
		s, e = engine.Status(id)
		if e == nil && s.LastTaskID == req.TaskID && s.LastResult == "failed_rolled_back" {
			recovered = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !recovered {
		t.Fatalf("independent timer did not recover killed publisher: %+v %v", s, e)
	}
	t.Log("T13: SIGKILL publisher, independent systemd timer + recovery executable restored service")
	oldA := req.Model.Nodes[0]
	oldA.Listen = "127.0.0.1"
	if e = Probe(ctx, filepath.Join(root, id, "versions", s.CurrentVersion), Model{Nodes: []Node{oldA}}); e == nil {
		t.Fatal("old recovery snapshot re-authorized expired A")
	}
	if e = Probe(ctx, filepath.Join(root, id, "versions", s.CurrentVersion), Model{Nodes: []Node{b}}); e != nil {
		t.Fatal(e)
	}
	t.Log("T19: independent recovery applied newest revocation policy to old snapshot")
	p.Groups["group-a"] = GroupPolicy{Version: 3, ExpiresAt: time.Now().Add(time.Hour)}
	s, e = engine.UpdatePolicies(ctx, id, p)
	if e != nil {
		t.Fatal("explicit renewal synchronization:", e)
	}
	// Persist an already-expired A policy; local scan must remove A and restart
	// the shared process, terminating old sessions without removing B.
	authorizedA := req.Model.Nodes[0]
	authorizedA.Listen = "127.0.0.1"
	stream, closeStream := testPersistentTunnel(t, authorizedA, cert)
	defer closeStream()
	p.Groups["group-a"] = GroupPolicy{Version: 4, ExpiresAt: time.Now().Add(-time.Second)}
	if e = writeJSON(filepath.Join(root, id, "policies.json"), p); e != nil {
		t.Fatal(e)
	}
	beforeExpiryVersion := s.CurrentVersion
	expiredByIndependentTimer := false
	for until := time.Now().Add(25 * time.Second); time.Now().Before(until); {
		s, e = engine.Status(id)
		if e == nil && s.LastResult == "succeeded" && s.CurrentVersion != beforeExpiryVersion {
			expiredByIndependentTimer = true
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !expiredByIndependentTimer {
		t.Fatalf("persistent independent expiry timer did not apply authorization: %+v %v", s, e)
	}
	dir = filepath.Join(root, id, "versions", s.CurrentVersion)
	if e = Probe(ctx, dir, Model{Nodes: []Node{authorizedA}}); e == nil {
		t.Fatal("expired A accepted")
	}
	_ = stream.SetDeadline(time.Now().Add(time.Second))
	_, _ = stream.Write([]byte("after-expiry"))
	reply := make([]byte, 1)
	if _, x := stream.Read(reply); x == nil {
		t.Fatal("pre-existing A stream survived expiry restart")
	}
	if e = Probe(ctx, dir, Model{Nodes: []Node{b}}); e != nil {
		t.Fatal("expiry removed B", e)
	}
	t.Log("T20: persistent independent policy timer withdrew A listener and terminated existing A stream; B remains usable")
	historical, err := engine.Receipt(id, "create-a-b")
	if err != nil || historical.LastResult != "succeeded" || historical.Generation != 1 {
		t.Fatal("later policy erased original immutable receipt")
	}
	fresh, err := engine.VerifyStatus(ctx, id)
	if err != nil || fresh.ObservedAt.Before(time.Now().Add(-3*time.Second)) {
		t.Fatal("fresh status verification failed")
	}
	if e = os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0440); e != nil {
		t.Fatal(e)
	}
	req.Generation = s.Generation + 1
	req.Fencing = s.Fencing + 1
	req.TaskID = "reject-drift"
	req.Policies = p
	if _, e = engine.Apply(ctx, req); e == nil {
		t.Fatal("configuration drift overwritten")
	}
	t.Log("T11/T18: drift refused and service uses only explicit current/config.json")
}
func testPersistentTunnel(t *testing.T, n Node, c Certificate) (net.Conn, func()) {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go func() {
		peer, x := ln.Accept()
		if x == nil {
			defer peer.Close()
			_, _ = io.Copy(peer, peer)
		}
	}()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(c.TrustPEM)
	conn, e := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", n.Port), &tls.Config{ServerName: n.ServerName, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if e != nil {
		ln.Close()
		t.Fatal(e)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	id, _ := DecodeUUID(n.UUID)
	header := append([]byte{0}, id...)
	header = append(header, 0, 1)
	header = binary.BigEndian.AppendUint16(header, uint16(ln.Addr().(*net.TCPAddr).Port))
	header = append(header, 1, 127, 0, 0, 1)
	header = append(header, []byte("ping")...)
	if _, e = conn.Write(header); e != nil {
		t.Fatal(e)
	}
	response := make([]byte, 6)
	if _, e = io.ReadFull(conn, response); e != nil || string(response[2:]) != "ping" {
		t.Fatalf("persistent authenticated tunnel: %v", e)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, func() { _ = conn.Close(); _ = ln.Close() }
}
