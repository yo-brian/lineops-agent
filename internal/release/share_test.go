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
