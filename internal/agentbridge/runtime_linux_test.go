//go:build linux

package agentbridge

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"lineop-agent/internal/release"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRealExecutorSystemdReleaseAndFailureReceipt(t *testing.T) {
	binary, helper, executor := os.Getenv("LINEOPS_TEST_SINGBOX"), os.Getenv("LINEOPS_TEST_RECOVERY"), os.Getenv("LINEOPS_TEST_EXECUTOR_BINARY")
	if binary == "" || helper == "" || executor == "" || os.Geteuid() != 0 {
		t.Skip("requires real isolated root Linux sing-box, recovery, and executor binaries")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	base, e := os.MkdirTemp("/var/lib", "lineops-bridge-acceptance-")
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(base, 0755)
	id := fmt.Sprintf("bridge-%d", time.Now().UnixNano())
	root := filepath.Join(base, "instances")
	executorUnit := "lineops-executor-" + id
	var registered bool
	defer func() {
		for _, unit := range []string{executorUnit + ".service", "lineops-policy-" + id + ".timer", "lineops-policy-" + id + ".service", "lineops-sing-box-" + id + ".service", "lineops-recover-" + id + "-*.timer"} {
			_ = exec.Command("/usr/bin/systemctl", "stop", unit).Run()
		}
		if registered {
			_ = exec.Command("/usr/bin/systemctl", "disable", "lineops-policy-"+id+".timer").Run()
			for _, unit := range []string{"lineops-policy-" + id + ".timer", "lineops-policy-" + id + ".service", "lineops-sing-box-" + id + ".service"} {
				_ = os.Remove(filepath.Join("/etc/systemd/system", unit))
			}
			_ = exec.Command("/usr/bin/systemctl", "daemon-reload").Run()
		}
		if strings.HasPrefix(base, "/var/lib/lineops-bridge-acceptance-") {
			_ = os.RemoveAll(base)
		}
	}()
	data, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(data)
	helperBytes, e := os.ReadFile(helper)
	if e != nil {
		t.Fatal(e)
	}
	helperHash := sha256.Sum256(helperBytes)
	t.Logf("runtime binaries: sing-box SHA256=%x recovery SHA256=%x", hash, helperHash)
	helper = filepath.Join(base, "lineops-recovery")
	if e = os.WriteFile(helper, helperBytes, 0755); e != nil {
		t.Fatal(e)
	}
	runtime := release.RuntimeConfig{InstanceID: id, Epoch: "isolated-bridge-epoch", Binary: binary, BinarySHA256: hex.EncodeToString(hash[:]), BinaryVersion: "1.14.0", RecoveryBinary: helper, ServiceUser: "lineops-release-test"}
	registered = true
	if e = release.Initialize(ctx, root, runtime); e != nil {
		t.Fatal(e)
	}
	program := filepath.Join(base, "lineops-executor")
	data, e = os.ReadFile(executor)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(program, data, 0755); e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(base, "socket", "executor.sock")
	agentUser, e := user.Lookup("lineops-release-test")
	if e != nil {
		t.Fatal(e)
	}
	agentGID, e := strconv.Atoi(agentUser.Gid)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Dir(socket), 0750); e != nil {
		t.Fatal(e)
	}
	if e = os.Chown(filepath.Dir(socket), 0, agentGID); e != nil {
		t.Fatal(e)
	}
	if out, e := exec.CommandContext(ctx, "/usr/bin/systemd-run", "--quiet", "--collect", "--unit="+executorUnit, "--property=User=root", "--property=Group=lineops-release-test", "--property=NoNewPrivileges=yes", "--property=PrivateTmp=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes", "--property=ProtectControlGroups=yes", "--property=LockPersonality=yes", "--property=MemoryMax=512M", "--property=TasksMax=64", "--property=ReadWritePaths="+root+" "+filepath.Dir(socket), program, "--root", root, "--socket", socket, "--agent-user", "lineops-release-test").CombinedOutput(); e != nil {
		t.Fatalf("isolated executor service: %s", out)
	}
	var client *Client
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		client, e = New(socket)
		if e == nil && client.Ready(ctx) == nil {
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if client == nil || client.Ready(ctx) != nil {
		t.Fatal("real executor service unavailable")
	}
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "LineOps executor isolated CA"}, DNSNames: []string{"executor-test.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(caKey)
	if e != nil {
		t.Fatal(e)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certificate := release.Certificate{ID: "executor-ca", CertificatePEM: certPEM, TrustPEM: certPEM, PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}
	reserve, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	node := release.Node{ID: "executor-node", GroupID: "executor-group", CredentialID: "executor-credential", UUID: "66666666-6666-4666-8666-666666666666", Listen: "127.0.0.1", Port: uint16(port), ServerName: "executor-test.invalid", CertificateID: certificate.ID}
	request := release.Request{TaskID: "executor-initial", Epoch: runtime.Epoch, InstanceID: id, Generation: 1, Fencing: 1, TargetGroups: []string{node.GroupID}, Model: release.Model{Schema: 1, Template: release.Template, Nodes: []release.Node{node}}, Certificates: []release.Certificate{certificate}, Policies: release.PolicySet{Epoch: runtime.Epoch, Groups: map[string]release.GroupPolicy{node.GroupID: {Version: 1, ExpiresAt: time.Now().Add(time.Hour)}}}, RecoverySeconds: 15}
	state, e := client.Apply(ctx, request)
	if e != nil || state.LastResult != "succeeded" {
		t.Fatalf("real executor publication: state=%s error=%v", state.LastResult, e)
	}
	if e = release.Probe(ctx, filepath.Join(root, id, "versions", state.CurrentVersion), request.Model); e != nil {
		t.Fatal("published VLESS/TLS handshake failed")
	}
	verified, e := client.VerifyStatus(ctx, id)
	if e != nil || verified.LastResult != "succeeded" || verified.LastTaskID != request.TaskID {
		t.Fatalf("real current health verification failed: %s %v", verified.LastResult, e)
	}
	initialTask := request.TaskID
	request.TaskID = "executor-formal-failure"
	request.Generation = state.Generation + 1
	request.Fencing = state.Fencing + 1
	request.Model.Nodes[0].Listen = "192.0.2.99"
	state, e = client.Apply(ctx, request)
	if e == nil || state.LastResult != "failed_rolled_back" {
		t.Fatalf("failure receipt lost: %s %v", state.LastResult, e)
	}
	request.Model.Nodes[0].Listen = "127.0.0.1"
	if e = release.Probe(ctx, filepath.Join(root, id, "versions", state.CurrentVersion), request.Model); e != nil {
		t.Fatal("recovered endpoint handshake failed")
	}
	actual, e := client.Status(ctx, id)
	if e != nil || actual.LastResult != "failed_rolled_back" || actual.LastTaskID != request.TaskID {
		t.Fatal("real executor did not preserve failed operation status")
	}
	receipt, e := client.Receipt(ctx, id, initialTask)
	if e != nil || receipt.LastTaskID != initialTask || receipt.LastResult != "succeeded" || receipt.Generation != 1 {
		t.Fatalf("independent old receipt lost after newer task: %s %v", receipt.LastResult, e)
	}
	if e = exec.CommandContext(ctx, "/usr/bin/systemctl", "stop", "lineops-sing-box-"+id+".service").Run(); e != nil {
		t.Fatal(e)
	}
	verified, e = client.VerifyStatus(ctx, id)
	if e == nil || verified.LastResult == "succeeded" {
		t.Fatal("stopped service passed real VerifyStatus")
	}
	if e = client.Ready(ctx); e != nil {
		t.Fatal("executor readiness coupled to service health")
	}
	t.Log("real systemd executor -> root release -> sing-box TLS handshake; bind failure returned failed_rolled_back and restored previous endpoint")
	t.Log("VerifyStatus probes actual running service; stopped service rejected; original task receipt remains independently readable")
}
