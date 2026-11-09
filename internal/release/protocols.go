package release

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
)

const MultiProtocolTemplate = "proxy-direct-v2"
const TCPRelayTemplate = "tcp-relay-v1"

// ProtocolOptions is an explicit, comparable allowlist shared by publication
// and subscription rendering. It never contains a private key or password.
type ProtocolOptions struct {
	RelayAddress                 string `json:"relay_address,omitempty"`
	RelayPort                    uint16 `json:"relay_port,omitempty"`
	Protocol                     string `json:"protocol,omitempty"`
	Security                     string `json:"security,omitempty"`
	Transport                    string `json:"transport,omitempty"`
	Flow                         string `json:"flow,omitempty"`
	TransportPath                string `json:"transport_path,omitempty"`
	TransportHost                string `json:"transport_host,omitempty"`
	GRPCServiceName              string `json:"grpc_service_name,omitempty"`
	Method                       string `json:"method,omitempty"`
	RealityHandshake             string `json:"reality_handshake,omitempty"`
	RealityHandshakePort         uint16 `json:"reality_handshake_port,omitempty"`
	RealityPublicKey             string `json:"reality_public_key,omitempty"`
	RealityShortID               string `json:"reality_short_id,omitempty"`
	RealitySpiderX               string `json:"reality_spider_x,omitempty"`
	RealitySupportX25519MLKEM768 bool   `json:"reality_support_x25519mlkem768,omitempty"`
}

func (o ProtocolOptions) Normalized() ProtocolOptions {
	if o.Protocol == "" {
		o.Protocol = "vless"
	}
	if o.Transport == "" {
		if o.Protocol == "hysteria2" {
			o.Transport = "quic"
		} else {
			o.Transport = "tcp"
		}
	}
	if o.Security == "" {
		if o.Protocol == "shadowsocks" {
			o.Security = "none"
		} else {
			o.Security = "tls"
		}
	}
	return o
}

var serverNamePattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
var grpcNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)
var shortIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

func (o ProtocolOptions) Validate() error {
	return o.validate(o.RelayAddress != "" || o.RelayPort != 0)
}

func (o ProtocolOptions) validate(clientOnly bool) error {
	o = o.Normalized()
	if o.RelayAddress != "" || o.RelayPort != 0 {
		if o.Protocol == "hysteria2" {
			return errors.New("TCP 中转不支持 Hysteria 2（QUIC/UDP）协议")
		}
		if !PublicRelayIP(o.RelayAddress) || o.RelayPort == 0 {
			return errors.New("TCP 中转需要固定公网落地 IP 和端口")
		}
		clientOnly = true
	}
	switch o.Protocol {
	case "vless":
		if o.Security != "tls" && o.Security != "reality" {
			return errors.New("VLESS 需要 TLS 或 Reality")
		}
	case "vmess", "trojan":
		if o.Security != "tls" {
			return errors.New("VMess/Trojan 当前需要 TLS")
		}
	case "anytls":
		if o.Security != "tls" || o.Transport != "tcp" {
			return errors.New("AnyTLS 当前需要 TLS 和 TCP 传输")
		}
	case "hysteria2":
		if o.Security != "tls" || o.Transport != "quic" {
			return errors.New("Hysteria 2 当前需要 TLS 和 QUIC（UDP）传输")
		}
	case "shadowsocks":
		if o.Security != "none" || o.Transport != "tcp" {
			return errors.New("Shadowsocks 使用自身加密和 TCP，不叠加 TLS/Reality/WS/gRPC")
		}
	default:
		return errors.New("不支持的节点协议")
	}
	if o.Flow != "" && (o.Protocol != "vless" || o.Flow != "xtls-rprx-vision" || o.Transport != "tcp") {
		return errors.New("Vision 仅支持 VLESS 的 TCP 传输")
	}
	switch o.Transport {
	case "tcp":
		if o.Protocol == "hysteria2" {
			return errors.New("Hysteria 2 使用 QUIC（UDP）传输")
		}
		if o.TransportPath != "" || o.TransportHost != "" || o.GRPCServiceName != "" {
			return errors.New("TCP 不接受 WS/gRPC 参数")
		}
	case "quic":
		if o.Protocol != "hysteria2" {
			return errors.New("QUIC（UDP）传输当前仅用于 Hysteria 2")
		}
		if o.TransportPath != "" || o.TransportHost != "" || o.GRPCServiceName != "" {
			return errors.New("QUIC（UDP）不接受 WS/gRPC 参数")
		}
	case "ws":
		if len(o.TransportPath) == 0 || len(o.TransportPath) > 256 || !strings.HasPrefix(o.TransportPath, "/") || strings.ContainsAny(o.TransportPath, "\r\n\t #") || o.GRPCServiceName != "" {
			return errors.New("WebSocket 路径必须以 / 开头，不能含空白或片段标记")
		}
		if o.TransportHost != "" && !serverNamePattern.MatchString(o.TransportHost) {
			return errors.New("WebSocket Host 格式无效")
		}
	case "grpc":
		if !grpcNamePattern.MatchString(o.GRPCServiceName) || o.TransportPath != "" || o.TransportHost != "" {
			return errors.New("gRPC 服务名仅允许 1–128 位字母、数字、下划线和短横线")
		}
	default:
		return errors.New("传输仅支持 TCP、WebSocket、gRPC、QUIC")
	}
	if o.Protocol == "shadowsocks" {
		switch o.Method {
		case "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm":
		default:
			return errors.New("不支持的 Shadowsocks 加密方式")
		}
	} else if o.Method != "" {
		return errors.New("加密方式字段仅用于 Shadowsocks")
	}
	if o.Security == "reality" {
		if o.Transport != "tcp" {
			return errors.New("Reality 当前仅支持 TCP，可选 Vision")
		}
		if !clientOnly && (!validHandshake(o.RealityHandshake) || o.RealityHandshakePort == 0) {
			return errors.New("Reality 握手目标需要主机名或 IP 及有效端口")
		}
		key, err := base64.RawURLEncoding.DecodeString(o.RealityPublicKey)
		validShortID := shortIDPattern.MatchString(o.RealityShortID)
		if clientOnly {
			_, e := hex.DecodeString(o.RealityShortID)
			validShortID = e == nil && len(o.RealityShortID) <= 16
		}
		if err != nil || len(key) != 32 || !validShortID {
			return errors.New("Reality 公钥或 short ID 无效")
		}
	} else if o.RealityHandshake != "" || o.RealityHandshakePort != 0 || o.RealityPublicKey != "" || o.RealityShortID != "" || o.RealitySpiderX != "" || o.RealitySupportX25519MLKEM768 {
		return errors.New("非 Reality 节点不能包含 Reality 参数")
	}
	return nil
}

func validHandshake(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast()
	}
	return serverNamePattern.MatchString(host) && !strings.Contains(host, "..")
}

func NewRealityKey() (private, public, shortID string, err error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", "", err
	}
	id := make([]byte, 8)
	if _, err = rand.Read(id); err != nil {
		return "", "", "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.Bytes()), base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), hex.EncodeToString(id), nil
}

func (o ProtocolOptions) NewPassword() (string, error) {
	size := 32
	if o.Method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (n Node) UsesCertificate() bool {
	return n.RelayAddress == "" && n.ProtocolOptions.Normalized().Security == "tls"
}

// ListenerNetwork returns the host socket transport ("udp" or "tcp") bound by
// the managed inbound listener, distinct from the proxied application traffic.
func (n Node) ListenerNetwork() string {
	if n.RelayAddress == "" && n.ProtocolOptions.Normalized().Protocol == "hysteria2" {
		return "udp"
	}
	return "tcp"
}

func PublicRelayIP(host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.Zone() == "" && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}
func (n Node) credential() string {
	if p := n.ProtocolOptions.Normalized().Protocol; p == "vless" || p == "vmess" {
		return n.UUID
	}
	return n.Password
}
func (n Node) validateProtocol() error {
	return n.validateProtocolMode(false)
}
func (n Node) validateProtocolMode(clientOnly bool) error {
	o := n.ProtocolOptions.Normalized()
	clientMode := clientOnly || n.RelayAddress != ""
	if n.RelayTrustPEM != "" {
		if n.RelayAddress == "" || o.Security != "tls" || len(n.RelayTrustPEM) > 1<<20 || !x509.NewCertPool().AppendCertsFromPEM([]byte(n.RelayTrustPEM)) {
			return errors.New("invalid relay trust certificate")
		}
	}
	if err := o.validate(clientMode); err != nil {
		return err
	}
	if o.Protocol == "vless" || o.Protocol == "vmess" {
		if !uuidPattern.MatchString(n.UUID) || n.Password != "" {
			return errors.New("UUID credential required")
		}
	} else {
		if n.UUID != "" || len(n.Password) == 0 || (!clientMode && len(n.Password) < 16) || len(n.Password) > 128 || strings.ContainsAny(n.Password, "\r\n\x00") {
			return errors.New("password credential required")
		}
		if strings.HasPrefix(o.Method, "2022-") {
			size := 32
			if o.Method == "2022-blake3-aes-128-gcm" {
				size = 16
			}
			keys := strings.Split(n.Password, ":")
			// Managed server inbounds still require one key. Client/relay
			// passwords may include the server identity and user keys.
			if !clientMode && len(keys) != 1 {
				return errors.New("invalid Shadowsocks 2022 server key")
			}
			for _, encoded := range keys {
				key, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil || len(key) != size {
					return errors.New("invalid Shadowsocks 2022 key")
				}
			}
		}
	}
	if !clientOnly && n.UsesCertificate() {
		if !identifier.MatchString(n.CertificateID) || !serverNamePattern.MatchString(n.ServerName) {
			return errors.New("TLS certificate and server name required")
		}
	} else if n.CertificateID != "" {
		return errors.New("unexpected certificate dependency")
	}
	if clientMode {
		if n.RealityPrivateKey != "" || (o.Security != "none" && !serverNamePattern.MatchString(n.ServerName)) {
			return errors.New("relay requires client TLS parameters only")
		}
	} else if o.Security == "reality" {
		if !serverNamePattern.MatchString(n.ServerName) {
			return errors.New("Reality server name required")
		}
		private, err := base64.RawURLEncoding.DecodeString(n.RealityPrivateKey)
		if err != nil {
			return errors.New("invalid Reality private key")
		}
		key, err := ecdh.X25519().NewPrivateKey(private)
		if err != nil || base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) != o.RealityPublicKey {
			return errors.New("Reality key pair mismatch")
		}
	} else if n.RealityPrivateKey != "" {
		return errors.New("unexpected Reality private key")
	}
	if o.Security == "none" && n.ServerName != "" {
		return errors.New("unexpected TLS server name")
	}
	return nil
}

func ModelTemplate(nodes []Node) string {
	for _, n := range nodes {
		if n.SSMultiUser {
			return TeamSSTemplate
		}
	}
	for _, n := range nodes {
		if len(n.Users) > 0 || n.LegacyDisabled {
			return TeamTemplate
		}
	}
	for _, n := range nodes {
		if n.RelayAddress != "" {
			return TCPRelayTemplate
		}
	}
	legacy := (ProtocolOptions{}).Normalized()
	for _, n := range nodes {
		if n.ProtocolOptions.Normalized() != legacy {
			return MultiProtocolTemplate
		}
	}
	return Template
}

func transportOptions(o ProtocolOptions) map[string]any {
	switch o.Transport {
	case "ws":
		out := map[string]any{"type": "ws", "path": o.TransportPath}
		if o.TransportHost != "" {
			out["headers"] = map[string]string{"Host": o.TransportHost}
		}
		return out
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": o.GRPCServiceName}
	}
	return nil
}

func inbound(n Node, dir string) map[string]any {
	if n.RelayAddress != "" {
		return map[string]any{"type": "direct", "tag": "node-" + n.ID, "listen": n.Listen, "listen_port": n.Port, "network": "tcp", "override_address": n.RelayAddress, "override_port": n.RelayPort}
	}
	o := n.ProtocolOptions.Normalized()
	out := map[string]any{"type": o.Protocol, "tag": "node-" + n.ID, "listen": n.Listen, "listen_port": n.Port}
	user := map[string]string{"name": "credential-" + n.CredentialID}
	switch o.Protocol {
	case "vless", "vmess":
		user["uuid"] = n.UUID
		if o.Flow != "" {
			user["flow"] = o.Flow
		}
		out["users"] = []any{user}
	case "trojan", "anytls", "hysteria2":
		user["password"] = n.Password
		out["users"] = []any{user}
	case "shadowsocks":
		out["method"] = o.Method
		out["password"] = n.Password
		out["network"] = "tcp"
	}
	if n.SupportsUsers() && (o.Protocol != "shadowsocks" || n.SSMultiUser) {
		users := []any{}
		for _, v := range n.authenticationIdentities() {
			user := map[string]string{"name": "credential-" + v.CredentialID}
			if o.Protocol == "trojan" || o.Protocol == "anytls" || o.Protocol == "hysteria2" || o.Protocol == "shadowsocks" {
				user["password"] = v.Password
			} else {
				user["uuid"] = v.UUID
				if o.Flow != "" {
					user["flow"] = o.Flow
				}
			}
			users = append(users, user)
		}
		out["users"] = users
		if o.Protocol == "shadowsocks" && strings.HasPrefix(o.Method, "2022-") {
			out["password"] = o.SSServerKey(n.Password)
		}
	}
	if o.Security == "tls" {
		out["tls"] = map[string]any{"enabled": true, "server_name": n.ServerName, "min_version": "1.2", "certificate_path": filepath.Join(dir, "tls-"+n.CertificateID+".pem"), "key_path": filepath.Join(dir, "key-"+n.CertificateID+".pem")}
	} else if o.Security == "reality" {
		out["tls"] = map[string]any{"enabled": true, "server_name": n.ServerName, "reality": map[string]any{"enabled": true, "handshake": map[string]any{"server": o.RealityHandshake, "server_port": o.RealityHandshakePort}, "private_key": n.RealityPrivateKey, "short_id": []string{o.RealityShortID}}}
	}
	if transport := transportOptions(o); transport != nil {
		out["transport"] = transport
	}
	return out
}

// ClientOutbound and MihomoProxy intentionally copy only client-side fields.
// Neither exposes a Reality private key or its server-side handshake target.
func ClientOutbound(n Node, address string) map[string]any {
	o := n.ProtocolOptions.Normalized()
	out := map[string]any{"type": o.Protocol, "tag": "node-" + n.ID, "server": address, "server_port": n.Port}
	if o.Protocol != "anytls" && o.Protocol != "hysteria2" {
		out["network"] = "tcp"
	}
	switch o.Protocol {
	case "vless", "vmess":
		out["uuid"] = n.UUID
		if o.Flow != "" {
			out["flow"] = o.Flow
		}
		if o.Protocol == "vmess" {
			out["security"] = "auto"
			out["alter_id"] = 0
		}
	case "trojan", "anytls", "hysteria2", "shadowsocks":
		out["password"] = n.Password
	}
	if o.Method != "" {
		out["method"] = o.Method
	}
	if o.Security != "none" {
		tls := map[string]any{"enabled": true, "server_name": n.ServerName}
		if o.Security == "reality" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
			tls["reality"] = map[string]any{"enabled": true, "public_key": o.RealityPublicKey, "short_id": o.RealityShortID}
		}
		out["tls"] = tls
	}
	if transport := transportOptions(o); transport != nil {
		out["transport"] = transport
	}
	return out
}

func MihomoProxy(n Node, address string) map[string]any {
	o := n.ProtocolOptions.Normalized()
	protocol := o.Protocol
	if protocol == "shadowsocks" {
		protocol = "ss"
	}
	out := map[string]any{"name": "node-" + n.ID, "type": protocol, "server": address, "port": n.Port, "udp": o.Protocol == "hysteria2"}
	if o.Protocol == "vless" || o.Protocol == "vmess" {
		out["uuid"] = n.UUID
	} else {
		out["password"] = n.Password
	}
	if o.Protocol == "vmess" {
		out["alterId"] = 0
		out["cipher"] = "auto"
	}
	if o.Method != "" {
		out["cipher"] = o.Method
	}
	if o.Flow != "" {
		out["flow"] = o.Flow
	}
	if o.Security != "none" {
		if o.Protocol != "hysteria2" {
			out["tls"] = true
		}
		out["skip-cert-verify"] = false
		if o.Protocol == "trojan" || o.Protocol == "anytls" || o.Protocol == "hysteria2" {
			out["sni"] = n.ServerName
		} else {
			out["servername"] = n.ServerName
		}
		if o.Security == "reality" {
			out["client-fingerprint"] = "chrome"
			out["reality-opts"] = map[string]any{"public-key": o.RealityPublicKey, "short-id": o.RealityShortID}
			if o.RealitySupportX25519MLKEM768 {
				out["reality-opts"].(map[string]any)["support-x25519mlkem768"] = true
			}
		}
	}
	if o.Protocol != "shadowsocks" && o.Protocol != "anytls" && o.Protocol != "hysteria2" {
		out["network"] = o.Transport
	}
	if o.Transport == "ws" {
		ws := map[string]any{"path": o.TransportPath}
		if o.TransportHost != "" {
			ws["headers"] = map[string]string{"Host": o.TransportHost}
		}
		out["ws-opts"] = ws
	}
	if o.Transport == "grpc" {
		out["grpc-opts"] = map[string]string{"grpc-service-name": o.GRPCServiceName}
	}
	return out
}
