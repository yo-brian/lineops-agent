package release

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

// ParseShareURI accepts client credentials only. It never fetches a URL.
func ParseShareURI(raw string) (Node, string, error) {
	fail := func() (Node, string, error) { return Node{}, "", errors.New("不支持或无效的节点分享链接") }
	if len(raw) > 8192 || strings.ContainsAny(raw, "\r\n") {
		return fail()
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fail()
	}
	decode := func(s string) ([]byte, error) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, e := enc.DecodeString(s); e == nil {
				return b, nil
			}
		}
		return nil, errors.New("invalid base64")
	}
	n := Node{}
	host := u.Hostname()
	port, e := strconv.Atoi(u.Port())
	if u.Scheme == "vmess" {
		data, e := decode(strings.TrimPrefix(strings.TrimSpace(raw), "vmess://"))
		if e != nil {
			return fail()
		}
		var v map[string]json.RawMessage
		if json.Unmarshal(data, &v) != nil {
			return fail()
		}
		get := func(k string) string {
			var s string
			if json.Unmarshal(v[k], &s) == nil {
				return s
			}
			return string(v[k])
		}
		if get("tls") != "tls" || (get("aid") != "" && get("aid") != "0") || (get("scy") != "" && get("scy") != "auto") {
			return fail()
		}
		host = get("add")
		port, e = strconv.Atoi(get("port"))
		if e != nil {
			return fail()
		}
		n.ProtocolOptions = ProtocolOptions{Protocol: "vmess", Security: "tls", Transport: get("net")}
		n.UUID = get("id")
		n.ServerName = get("sni")
		if n.ServerName == "" {
			n.ServerName = get("host")
		}
		if n.ServerName == "" {
			n.ServerName = host
		}
		if n.Transport == "ws" {
			n.TransportHost = get("host")
			n.TransportPath = get("path")
		}
		if n.Transport == "grpc" {
			n.GRPCServiceName = get("path")
		}
	} else {
		if u.User == nil || e != nil {
			return fail()
		}
		q := u.Query()
		for k := range q {
			switch k {
			case "security", "type", "sni", "flow", "encryption", "pbk", "sid", "fp", "path", "host", "serviceName", "mode", "spx", "support-x25519mlkem768", "insecure":
			default:
				return fail()
			}
		}
		if q.Has("insecure") {
			if (u.Scheme != "hysteria2" && u.Scheme != "hy2") || (q.Get("insecure") != "" && q.Get("insecure") != "0" && q.Get("insecure") != "false") {
				return fail()
			}
		}
		if enc := q.Get("encryption"); enc != "" && enc != "none" {
			if u.Scheme != "vless" || !vlessEncryptionPattern.MatchString(enc) {
				return fail()
			}
		}
		if q.Get("fp") != "" && q.Get("fp") != "chrome" {
			return fail()
		}
		if q.Get("mode") != "" && q.Get("mode") != "gun" {
			return fail()
		}
		scheme := u.Scheme
		if scheme == "hy2" {
			scheme = "hysteria2"
		}
		n.ProtocolOptions = ProtocolOptions{Protocol: scheme, Security: q.Get("security"), Transport: q.Get("type"), Flow: q.Get("flow"), Encryption: q.Get("encryption"), TransportPath: q.Get("path"), TransportHost: q.Get("host"), GRPCServiceName: q.Get("serviceName"), RealityPublicKey: q.Get("pbk"), RealityShortID: q.Get("sid")}.Normalized()
		n.ServerName = q.Get("sni")
		if q.Has("spx") || q.Has("support-x25519mlkem768") {
			if scheme != "vless" || n.Security != "reality" {
				return fail()
			}
			n.RealitySpiderX = q.Get("spx")
			if q.Has("support-x25519mlkem768") {
				if q.Get("support-x25519mlkem768") != "true" && q.Get("support-x25519mlkem768") != "false" {
					return fail()
				}
				n.RealitySupportX25519MLKEM768 = q.Get("support-x25519mlkem768") == "true"
			}
		}
		if n.ServerName == "" && n.Security != "none" {
			n.ServerName = host
		}
		switch scheme {
		case "vless":
			n.UUID = u.User.Username()
		case "trojan", "anytls":
			n.Password = u.User.Username()
		case "hysteria2":
			if (q.Get("security") != "" && q.Get("security") != "tls") || (q.Get("type") != "" && q.Get("type") != "quic") || q.Get("flow") != "" || q.Get("path") != "" || q.Get("host") != "" || q.Get("serviceName") != "" || q.Get("pbk") != "" || q.Get("sid") != "" {
				return fail()
			}
			n.ProtocolOptions = ProtocolOptions{Protocol: "hysteria2", Security: "tls", Transport: "quic"}
			n.Password = u.User.Username()
		case "ss":
			n.ProtocolOptions = ProtocolOptions{Protocol: "shadowsocks", Security: "none", Transport: "tcp"}
			n.ServerName = ""
			if password, ok := u.User.Password(); ok {
				n.Method = u.User.Username()
				n.Password = password
			} else {
				b, e := decode(u.User.Username())
				if e != nil {
					return fail()
				}
				parts := strings.SplitN(string(b), ":", 2)
				if len(parts) != 2 {
					return fail()
				}
				n.Method = parts[0]
				n.Password = parts[1]
			}
		default:
			return fail()
		}
	}
	if host == "" || port < 1 || port > 65535 {
		return fail()
	}
	n.ProtocolOptions = n.ProtocolOptions.Normalized()
	n.RelayAddress = host
	n.RelayPort = uint16(port)
	return n, host, nil
}
