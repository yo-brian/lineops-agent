package release

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func relayFixture() Node {
	return Node{ProtocolOptions: ProtocolOptions{Protocol: "vless", Security: "tls", Transport: "tcp", RelayAddress: "8.8.8.8", RelayPort: 443}, ID: "entry", GroupID: "group", CredentialID: "credential", UUID: "11111111-1111-4111-8111-111111111111", Listen: "127.0.0.1", Port: 20443, ServerName: "landing.example"}
}
func TestTCPRelayRenderPolicyAndValidation(t *testing.T) {
	n := relayFixture()
	m := Model{Schema: 1, Template: TCPRelayTemplate, Nodes: []Node{n}}
	if err := ValidateModel(m, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	data, err := Render(m, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), n.UUID) || strings.Contains(string(data), "tls") {
		t.Fatal("entry config must contain no landing credential or TLS termination")
	}
	var config map[string]any
	if json.Unmarshal(data, &config) != nil {
		t.Fatal("invalid JSON")
	}
	in := config["inbounds"].([]any)[0].(map[string]any)
	if in["type"] != "direct" || in["network"] != "tcp" || in["override_address"] != n.RelayAddress || in["override_port"] != float64(n.RelayPort) {
		t.Fatal("incorrect fixed TCP destination")
	}
	for _, host := range []string{"127.0.0.1", "::1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::ffff:192.168.1.1", "example.com"} {
		m.Nodes[0].RelayAddress = host
		if ValidateModel(m, nil, time.Now()) == nil {
			t.Fatalf("unsafe/unpinned address accepted: %s", host)
		}
	}
	m.Nodes[0] = n
	m.Template = MultiProtocolTemplate
	if ValidateModel(m, nil, time.Now()) == nil {
		t.Fatal("old capability accepted relay")
	}
	m.Template = TCPRelayTemplate
	hyRelay := n
	hyRelay.UUID = ""
	hyRelay.Password = "hysteria2-relay-secret"
	hyRelay.ProtocolOptions = ProtocolOptions{Protocol: "hysteria2", Security: "tls", Transport: "quic", RelayAddress: "8.8.8.8", RelayPort: 443}
	if ValidateModel(Model{Schema: 1, Template: TCPRelayTemplate, Nodes: []Node{hyRelay}}, nil, time.Now()) == nil {
		t.Fatal("TCP relay accepted QUIC/UDP Hysteria 2")
	}
	p := PolicySet{Groups: map[string]GroupPolicy{"group": {Version: 1, ExpiresAt: time.Now().Add(-time.Second)}}}
	effective, err := p.Effective(m, time.Now())
	if err != nil || len(effective.Nodes) != 0 {
		t.Fatal("expired relay retained")
	}
	p.Groups["group"] = GroupPolicy{Version: 2, ExpiresAt: time.Now().Add(time.Hour), RevokedCredentialIDs: []string{"credential"}}
	effective, err = p.Effective(m, time.Now())
	if err != nil || len(effective.Nodes) != 0 {
		t.Fatal("revoked relay retained")
	}
}

func TestTCPRelayShareParsing(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess", "trojan", "anytls", "shadowsocks"} {
		n := relayFixture()
		n.Protocol = protocol
		if protocol == "trojan" || protocol == "anytls" || protocol == "shadowsocks" {
			n.UUID = ""
			n.Password = "secret@:/?#&"
		}
		if protocol == "shadowsocks" {
			n.Security = "none"
			n.Method = "aes-128-gcm"
			n.ServerName = ""
		}
		raw := ShareURI(n, "2001:4860:4860::8888", "test")
		parsed, host, err := ParseShareURI(raw)
		if err != nil {
			t.Fatal(err)
		}
		if host != "2001:4860:4860::8888" || parsed.RelayPort != n.Port || parsed.UUID != n.UUID || parsed.Password != n.Password || parsed.ServerName != n.ServerName {
			t.Fatal("share roundtrip changed client parameters", protocol)
		}
	}
	for _, raw := range []string{"https://example.com/sub", "vless://id@host:0", "trojan://pass@host:443?allowInsecure=1", "vless://id@host:443?encryption=unsupported"} {
		if _, _, err := ParseShareURI(raw); err == nil {
			t.Fatal("unsupported share link accepted")
		}
	}
}

func TestTCPRelayTrialRejectsMissingListener(t *testing.T) {
	m := Model{Nodes: []Node{relayFixture()}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if probeTrialRelays(ctx, m) == nil {
		t.Fatal("missing listener reported healthy")
	}
}
