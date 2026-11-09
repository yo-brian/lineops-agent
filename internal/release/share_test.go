package release

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestShareURI(t *testing.T) {
	n := Node{Port: 443, ServerName: "example.com", UUID: "example-uuid", Password: "p@ss:/+#"}
	n.ProtocolOptions = ProtocolOptions{Protocol: "vless", Security: "reality", Transport: "tcp", Flow: "xtls-rprx-vision", RealityPublicKey: "public-key", RealityShortID: "0123456789abcdef"}
	raw := ShareURI(n, "2001:db8::1", "?? #1")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "[2001:db8::1]:443" || u.Fragment != "?? #1" || u.Query().Get("pbk") != "public-key" || u.Query().Get("flow") != "xtls-rprx-vision" {
		t.Fatal("Reality/IPv6/name mapping failed")
	}
	n.ProtocolOptions = ProtocolOptions{Protocol: "trojan", Security: "tls", Transport: "ws", TransportPath: "/a?x=1&y=2", TransportHost: "ws.example.com"}
	u, _ = url.Parse(ShareURI(n, "example.com", "test"))
	if u.User.Username() != n.Password || u.Query().Get("path") != n.TransportPath || u.Query().Get("host") != n.TransportHost {
		t.Fatal("password or WS escaping failed")
	}
	n.ProtocolOptions = ProtocolOptions{Protocol: "anytls", Security: "tls", Transport: "tcp"}
	u, _ = url.Parse(ShareURI(n, "example.com", "anytls-node"))
	if u.Scheme != "anytls" || u.User.Username() != n.Password || u.Query().Get("security") != "tls" || u.Query().Get("sni") != n.ServerName || u.Query().Get("type") != "tcp" || u.Fragment != "anytls-node" {
		t.Fatal("AnyTLS share URI mapping failed")
	}
	n.ProtocolOptions = ProtocolOptions{Protocol: "hysteria2", Security: "tls", Transport: "quic"}
	hyRaw := ShareURI(n, "example.com", "hy2-node")
	u, _ = url.Parse(hyRaw)
	if u.Scheme != "hysteria2" || u.User.Username() != n.Password || u.Query().Get("sni") != n.ServerName || u.Fragment != "hy2-node" {
		t.Fatal("Hysteria 2 share URI mapping failed")
	}
	parsedHy, hyHost, err := ParseShareURI(hyRaw)
	if err != nil || hyHost != "example.com" || parsedHy.Protocol != "hysteria2" || parsedHy.Transport != "quic" || parsedHy.Security != "tls" || parsedHy.Password != n.Password || parsedHy.ServerName != n.ServerName {
		t.Fatalf("Hysteria 2 share URI parse failed: %v %+v", err, parsedHy)
	}
	if parsedAlias, _, err := ParseShareURI("hy2://secret1234@example.com:8443?sni=hy.example.com&insecure=0#alias"); err != nil || parsedAlias.Protocol != "hysteria2" || parsedAlias.Transport != "quic" || parsedAlias.Password != "secret1234" {
		t.Fatalf("hy2:// alias parse failed: %v %+v", err, parsedAlias)
	}
	for _, badHy := range []string{
		"hysteria2://secret1234@example.com:8443?sni=hy.example.com&insecure=1",
		"hy2://secret1234@example.com:8443?sni=hy.example.com&type=ws",
		"hysteria2://secret1234@example.com:8443?sni=hy.example.com&security=reality",
	} {
		if _, _, err := ParseShareURI(badHy); err == nil {
			t.Fatalf("accepted unsafe or incompatible Hysteria 2 share link: %s", badHy)
		}
	}
	n.ProtocolOptions = ProtocolOptions{Protocol: "vmess", Security: "tls", Transport: "grpc", GRPCServiceName: "rpc"}
	data, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ShareURI(n, "example.com", "test"), "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if json.Unmarshal(data, &v) != nil || v["path"] != "rpc" || v["sni"] != n.ServerName || v["id"] != n.UUID {
		t.Fatal("VMess gRPC mapping failed")
	}
	for _, method := range []string{"aes-128-gcm", "2022-blake3-aes-128-gcm"} {
		n.ProtocolOptions = ProtocolOptions{Protocol: "shadowsocks", Method: method}
		u, _ = url.Parse(ShareURI(n, "example.com", "test"))
		if strings.HasPrefix(method, "2022-") {
			p, _ := u.User.Password()
			if p != n.Password || u.User.Username() != method {
				t.Fatal("SS2022 escaping failed")
			}
		} else {
			d, e := base64.RawURLEncoding.DecodeString(u.User.Username())
			if e != nil || string(d) != method+":"+n.Password {
				t.Fatal("SIP002 encoding failed")
			}
		}
	}
}
