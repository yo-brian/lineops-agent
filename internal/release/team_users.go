package release

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

const TeamTemplate = "team-users-v1"
const TeamSSTemplate = "team-users-ss-v1"

type UserCredential struct {
	ID       string `json:"id"`
	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
}

func (n Node) SupportsUsers() bool {
	p := n.ProtocolOptions.Normalized()
	return p.RelayAddress == "" && (p.Protocol == "vless" || p.Protocol == "vmess" || p.Protocol == "trojan" || p.Protocol == "anytls" || p.Protocol == "hysteria2" || p.Protocol == "shadowsocks")
}

// Derive a separate SS2022 server identity: a member receiving it must not learn
// the legacy user's password. Both remain stable until the root credential rotates.
func (o ProtocolOptions) SSServerKey(root string) string {
	sum := sha256.Sum256([]byte("lineops:ss2022-server:v1\x00" + root))
	size := 32
	if o.Method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	return base64.StdEncoding.EncodeToString(sum[:size])
}
func (o ProtocolOptions) SSClientPassword(root, user string, multi bool) string {
	if multi && o.Normalized().Protocol == "shadowsocks" && strings.HasPrefix(o.Method, "2022-") {
		return o.SSServerKey(root) + ":" + user
	}
	return user
}

// Authentication probes exercise every configured identity using the same
// listener, including shared identities. No duplicate server listeners exist.
func (n Node) AuthenticationNodes() []Node {
	out := n.authenticationIdentities()
	for i := range out {
		out[i].Password = n.ProtocolOptions.SSClientPassword(n.Password, out[i].Password, n.SSMultiUser)
		out[i].SSMultiUser = false
	}
	return out
}
func (n Node) authenticationIdentities() []Node {
	out := []Node{}
	if !n.LegacyDisabled {
		v := n
		v.Users = nil
		out = append(out, v)
	}
	for _, u := range n.Users {
		v := n
		v.ID = u.ID
		v.CredentialID = u.ID
		v.UUID = u.UUID
		v.Password = u.Password
		v.Users = nil
		v.LegacyDisabled = false
		out = append(out, v)
	}
	return out
}

func validateUsers(m Model) error {
	seen := map[string]bool{}
	count := 0
	for _, n := range m.Nodes {
		if (len(n.Users) > 0 || n.LegacyDisabled || n.SSMultiUser) && ((m.Template != TeamTemplate && m.Template != TeamSSTemplate) || !n.SupportsUsers()) {
			return errors.New("team credentials require supported authenticated inbound and team template")
		}
		if n.SSMultiUser && (n.ProtocolOptions.Normalized().Protocol != "shadowsocks" || m.Template != TeamSSTemplate || n.RelayAddress != "") {
			return errors.New("SS multi-user requires the SS team template")
		}
		if n.ProtocolOptions.Normalized().Protocol == "shadowsocks" && (len(n.Users) > 0 || n.LegacyDisabled) && !n.SSMultiUser {
			return errors.New("SS identities require multi-user mode")
		}
		if len(n.Users) > 64 {
			return errors.New("at most 64 independent identities per node")
		}
		for _, v := range n.authenticationIdentities() {
			if !identifier.MatchString(v.CredentialID) || seen[v.CredentialID] || seen["secret:"+v.credential()] {
				return errors.New("duplicate or invalid authentication identity")
			}
			if err := v.validateProtocol(); err != nil {
				return err
			}
			seen[v.CredentialID] = true
			seen["secret:"+v.credential()] = true
			count++
		}
	}
	if count > 1024 {
		return errors.New("at most 1024 authentication identities per instance")
	}
	return nil
}
