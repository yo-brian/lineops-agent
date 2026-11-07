package release

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func protocolMatrix() []ProtocolOptions {
	out := []ProtocolOptions{}
	for _, p := range []string{"vless", "vmess", "trojan"} {
		for _, transport := range []string{"tcp", "ws", "grpc"} {
			o := ProtocolOptions{Protocol: p, Security: "tls", Transport: transport}
			if transport == "ws" {
				o.TransportPath = "/lineops"
				o.TransportHost = "lineops-test.invalid"
			}
			if transport == "grpc" {
				o.GRPCServiceName = "lineops"
			}
			out = append(out, o)
		}
	}
	out = append(out, ProtocolOptions{Protocol: "vless", Security: "tls", Transport: "tcp", Flow: "xtls-rprx-vision"})
	for _, flow := range []string{"", "xtls-rprx-vision"} {
		out = append(out, ProtocolOptions{Protocol: "vless", Security: "reality", Transport: "tcp", Flow: flow, RealityHandshake: "127.0.0.1", RealityHandshakePort: 443})
	}
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		out = append(out, ProtocolOptions{Protocol: "shadowsocks", Security: "none", Transport: "tcp", Method: method})
	}
	return out
}

func TestProtocolCompatibilityAndSecretBoundaries(t *testing.T) {
	private, public, shortID, err := NewRealityKey()
	if err != nil {
		t.Fatal(err)
	}
	o := ProtocolOptions{Protocol: "vless", Security: "reality", Transport: "tcp", Flow: "xtls-rprx-vision", RealityHandshake: "handshake.example", RealityHandshakePort: 443, RealityPublicKey: public, RealityShortID: shortID}
	n := Node{ProtocolOptions: o, ID: "reality", GroupID: "group", CredentialID: "credential", UUID: "11111111-1111-4111-8111-111111111111", Listen: "127.0.0.1", Port: 15443, ServerName: "handshake.example", RealityPrivateKey: private}
	if err = n.validateProtocol(); err != nil {
		t.Fatal(err)
	}
	for _, config := range []any{ClientOutbound(n, "node.example"), MihomoProxy(n, "node.example")} {
		data, _ := json.Marshal(config)
		if strings.Contains(string(data), private) || strings.Contains(string(data), "private_key") || strings.Contains(string(data), "handshake\"") {
			t.Fatal("server secret/target leaked to subscription")
		}
		if !strings.Contains(string(data), public) || !strings.Contains(string(data), shortID) || !strings.Contains(string(data), "xtls-rprx-vision") {
			t.Fatal("client Reality/Vision fields missing")
		}
	}
	bad := []ProtocolOptions{
		{Protocol: "vmess", Security: "reality", Transport: "tcp"},
		{Protocol: "trojan", Security: "none", Transport: "tcp"},
		{Protocol: "vless", Security: "tls", Transport: "ws", Flow: "xtls-rprx-vision", TransportPath: "/test"},
		{Protocol: "vless", Security: "tls", Transport: "grpc", GRPCServiceName: "a/b"},
		{Protocol: "vless", Security: "tls", Transport: "ws", TransportPath: "/test\r\nHost: evil"},
		{Protocol: "shadowsocks", Security: "none", Transport: "tcp", Method: "none"},
		{Protocol: "vless", Security: "tls", Transport: "tcp", RealityPublicKey: public},
	}
	for _, options := range bad {
		if options.Validate() == nil {
			t.Fatalf("accepted invalid combination: %+v", options)
		}
	}
	legacy := Node{ID: "legacy", GroupID: "group", CredentialID: "credential", UUID: n.UUID, Listen: "127.0.0.1", Port: 15443, ServerName: "node.example", CertificateID: "cert"}
	normal := legacy
	normal.ProtocolOptions = normal.ProtocolOptions.Normalized()
	changed, err := SemanticDiff(Model{Nodes: []Node{legacy}}, Model{Nodes: []Node{normal}}, nil)
	if err != nil || len(changed) != 0 {
		t.Fatal("explicit defaults changed legacy semantics", err)
	}
	for _, options := range protocolMatrix() {
		if options.Protocol != "shadowsocks" {
			continue
		}
		password, err := options.NewPassword()
		if err != nil {
			t.Fatal(err)
		}
		ss := Node{ProtocolOptions: options, Password: password}
		if err = ss.validateProtocol(); err != nil {
			t.Fatal(options.Method, err)
		}
	}
}

func TestSS2022CompositeKeysClientOnly(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	n := Node{ProtocolOptions: ProtocolOptions{Protocol: "shadowsocks", Security: "none", Transport: "tcp", Method: "2022-blake3-aes-256-gcm"}, Password: key + ":" + key}
	if ValidateClientNode(n) != nil {
		t.Fatal("valid client composite key rejected")
	}
	if n.validateProtocol() == nil {
		t.Fatal("composite key accepted as managed server key")
	}
	n.Password = key
	if n.validateProtocol() != nil {
		t.Fatal("single server key rejected")
	}
}
