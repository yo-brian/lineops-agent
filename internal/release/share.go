package release

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// ShareURI renders a client-only link; server private keys are never serialized.
func ShareURI(n Node, address, name string) string {
	o := n.ProtocolOptions.Normalized()
	port := strconv.Itoa(int(n.Port))
	if o.Protocol == "vmess" {
		v := map[string]string{"v": "2", "ps": name, "add": address, "port": port, "id": n.UUID, "aid": "0", "scy": "auto", "net": o.Transport, "type": "none", "tls": "tls", "sni": n.ServerName}
		if o.Transport == "ws" {
			v["host"] = o.TransportHost
			v["path"] = o.TransportPath
		}
		if o.Transport == "grpc" {
			v["path"] = o.GRPCServiceName
			v["type"] = "gun"
		}
		data, _ := json.Marshal(v)
		return "vmess://" + base64.StdEncoding.EncodeToString(data)
	}
	u := url.URL{Scheme: o.Protocol, Host: net.JoinHostPort(address, port), Fragment: name}
	if o.Protocol == "shadowsocks" {
		u.Scheme = "ss"
		if strings.HasPrefix(o.Method, "2022-") {
			u.User = url.UserPassword(o.Method, n.Password)
		} else {
			u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(o.Method + ":" + n.Password)))
		}
		return u.String()
	}
	if o.Protocol == "hysteria2" {
		u.User = url.User(n.Password)
		u.RawQuery = url.Values{"sni": {n.ServerName}}.Encode()
		return u.String()
	}
	q := url.Values{"security": {o.Security}, "type": {o.Transport}}
	if n.ServerName != "" {
		q.Set("sni", n.ServerName)
	}
	if o.Protocol == "vless" {
		u.User = url.User(n.UUID)
		if o.Encryption != "" {
			q.Set("encryption", o.Encryption)
		} else {
			q.Set("encryption", "none")
		}
	} else {
		u.User = url.User(n.Password)
	}
	if o.Flow != "" {
		q.Set("flow", o.Flow)
	}
	if o.Security == "reality" {
		q.Set("pbk", o.RealityPublicKey)
		q.Set("sid", o.RealityShortID)
		q.Set("fp", "chrome")
		if o.RealitySpiderX != "" {
			q.Set("spx", o.RealitySpiderX)
		}
		if o.RealitySupportX25519MLKEM768 {
			q.Set("support-x25519mlkem768", "true")
		}
	}
	if o.Transport == "ws" {
		q.Set("path", o.TransportPath)
		if o.TransportHost != "" {
			q.Set("host", o.TransportHost)
		}
	}
	if o.Transport == "grpc" {
		q.Set("serviceName", o.GRPCServiceName)
		q.Set("mode", "gun")
	}
	u.RawQuery = q.Encode()
	return u.String()
}
