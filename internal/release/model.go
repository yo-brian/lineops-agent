// Package release implements the local, durable sing-box publication boundary.
// It accepts a fixed set of structured proxy models, never shell commands.
package release

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
)

const Template = "vless-tls-direct-v1"
const PreRenderedTemplate = "pre-rendered-singbox-v1"
const PortableVersionDir = "{{VERSION_DIR}}"

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

type Node struct {
	SSMultiUser    bool             `json:"ss_multi_user,omitempty"`
	Users          []UserCredential `json:"users,omitempty"`
	LegacyDisabled bool             `json:"legacy_disabled,omitempty"`
	ProtocolOptions
	RelayTrustPEM     string `json:"relay_trust_pem,omitempty"`
	ID                string `json:"id"`
	GroupID           string `json:"group_id"`
	CredentialID      string `json:"credential_id"`
	UUID              string `json:"uuid"`
	Password          string `json:"password,omitempty"`
	RealityPrivateKey string `json:"reality_private_key,omitempty"`
	Listen            string `json:"listen"`
	Port              uint16 `json:"port"`
	ServerName        string `json:"server_name"`
	CertificateID     string `json:"certificate_id"`
}
type Model struct {
	Schema   int    `json:"schema"`
	Template string `json:"template"`
	Nodes    []Node `json:"nodes"`
}
type Certificate struct {
	ID             string `json:"id"`
	CertificatePEM []byte `json:"certificate_pem"`
	PrivateKeyPEM  []byte `json:"private_key_pem"`
	TrustPEM       []byte `json:"trust_pem"`
}
type GroupPolicy struct {
	LegacyCredentialsDisabled bool      `json:"legacy_credentials_disabled,omitempty"`
	Version                   uint64    `json:"version"`
	ExpiresAt                 time.Time `json:"expires_at"`
	DisabledReasons           []string  `json:"disabled_reasons"`
	RevokedCredentialIDs      []string  `json:"revoked_credential_ids"`
}
type PolicySet struct {
	Epoch  string                 `json:"epoch"`
	Groups map[string]GroupPolicy `json:"groups"`
}
type Request struct {
	TaskID          string        `json:"task_id"`
	Epoch           string        `json:"epoch"`
	InstanceID      string        `json:"instance_id"`
	Generation      uint64        `json:"generation"`
	Fencing         uint64        `json:"fencing"`
	TargetGroups    []string      `json:"target_groups"`
	Model           Model         `json:"model"`
	RenderedConfig  []byte        `json:"rendered_config,omitempty"`
	Certificates    []Certificate `json:"certificates"`
	Policies        PolicySet     `json:"policies"`
	RecoverySeconds int           `json:"recovery_seconds"`
}

func (p PolicySet) Effective(m Model, now time.Time) (Model, error) {
	out := m
	out.Nodes = make([]Node, 0, len(m.Nodes))
	for _, n := range m.Nodes {
		g, ok := p.Groups[n.GroupID]
		if !ok || g.Version == 0 || g.ExpiresAt.IsZero() {
			return out, errors.New("missing authorization policy")
		}
		if g.LegacyCredentialsDisabled && n.SupportsUsers() {
			n.LegacyDisabled = true
			if out.Template != TeamSSTemplate {
				out.Template = TeamTemplate
			}
		}
		blocked := !now.Before(g.ExpiresAt) || len(g.DisabledReasons) > 0
		for _, id := range g.RevokedCredentialIDs {
			if id == n.CredentialID {
				blocked = true
			}
		}
		if !blocked {
			if len(n.Users) > 0 {
				users := []UserCredential{}
				for _, u := range n.Users {
					revoked := false
					for _, id := range g.RevokedCredentialIDs {
						if u.ID == id {
							revoked = true
							break
						}
					}
					if !revoked {
						users = append(users, u)
					}
				}
				n.Users = users
			}
			if n.LegacyDisabled && len(n.Users) == 0 {
				continue
			}
			out.Nodes = append(out.Nodes, n)
		}
	}
	return out, nil
}
func MergePolicies(old, next PolicySet) (PolicySet, error) {
	if old.Epoch != "" && old.Epoch != next.Epoch {
		return old, errors.New("deployment epoch requires manual reconciliation")
	}
	if !identifier.MatchString(next.Epoch) {
		return old, errors.New("invalid epoch")
	}
	out := PolicySet{Epoch: next.Epoch, Groups: map[string]GroupPolicy{}}
	for k, v := range old.Groups {
		out.Groups[k] = v
	}
	for k, v := range next.Groups {
		if !identifier.MatchString(k) || v.Version == 0 || v.ExpiresAt.IsZero() {
			return old, errors.New("invalid policy")
		}
		for _, r := range v.DisabledReasons {
			if r != "manual" && r != "security" && r != "maintenance" && r != "expired" && r != "restore_hold" {
				return old, errors.New("invalid disable reason")
			}
		}
		prev, ok := out.Groups[k]
		if ok && (v.Version < prev.Version || (v.Version == prev.Version && !(v.LegacyCredentialsDisabled == prev.LegacyCredentialsDisabled && v.ExpiresAt.Equal(prev.ExpiresAt) && reflect.DeepEqual(v.DisabledReasons, prev.DisabledReasons) && reflect.DeepEqual(v.RevokedCredentialIDs, prev.RevokedCredentialIDs)))) {
			return old, errors.New("stale or conflicting policy")
		}
		out.Groups[k] = v
	}
	return out, nil
}
func ValidateModel(m Model, certs []Certificate, now time.Time) error {
	if err := validateShape(m); err != nil {
		return err
	}
	if m.Schema != 1 || (m.Template != Template && m.Template != MultiProtocolTemplate && m.Template != TCPRelayTemplate && m.Template != TeamTemplate && m.Template != TeamSSTemplate) || len(m.Nodes) > 256 {
		return errors.New("unsupported model/template")
	}
	assets := map[string]Certificate{}
	for _, c := range certs {
		if !identifier.MatchString(c.ID) || len(c.CertificatePEM) > 1<<20 || len(c.PrivateKeyPEM) > 1<<20 || len(c.TrustPEM) > 1<<20 {
			return errors.New("invalid certificate asset")
		}
		if _, ok := assets[c.ID]; ok {
			return errors.New("duplicate certificate")
		}
		assets[c.ID] = c
	}
	seen := map[string]bool{}
	credentials := map[string]bool{}
	for i, n := range m.Nodes {
		if !identifier.MatchString(n.ID) || !identifier.MatchString(n.GroupID) || !identifier.MatchString(n.CredentialID) || n.Port < 1024 {
			return errors.New("invalid node; only unprivileged ports supported")
		}
		if seen[n.ID] || credentials[n.credential()] {
			return errors.New("duplicate node or credential")
		}
		seen[n.ID] = true
		credentials[n.credential()] = true
		ip, err := netip.ParseAddr(n.Listen)
		if err != nil || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return errors.New("invalid listen address")
		}
		for _, other := range m.Nodes[:i] {
			if PortConflict(n, other) {
				return errors.New("overlapping TCP listener")
			}
		}
		if !n.UsesCertificate() {
			continue
		}
		c, ok := assets[n.CertificateID]
		if !ok {
			return errors.New("missing certificate dependency")
		}
		pair, err := tls.X509KeyPair(c.CertificatePEM, c.PrivateKeyPEM)
		if err != nil {
			return errors.New("certificate and key mismatch")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return errors.New("invalid leaf certificate")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(c.TrustPEM) {
			return errors.New("explicit trusted CA required")
		}
		intermediates := x509.NewCertPool()
		for _, b := range pair.Certificate[1:] {
			parsed, e := x509.ParseCertificate(b)
			if e == nil {
				intermediates.AddCert(parsed)
			}
		}
		if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: n.ServerName, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return errors.New("TLS chain, SAN or validity rejected")
		}
	}
	return nil
}
func validateShape(m Model) error {
	if err := validateUsers(m); err != nil {
		return err
	}
	if m.Schema != 1 || (m.Template != Template && m.Template != MultiProtocolTemplate && m.Template != TCPRelayTemplate && m.Template != TeamTemplate && m.Template != TeamSSTemplate) || len(m.Nodes) > 256 {
		return errors.New("unsupported model/template")
	}
	ids := map[string]bool{}
	credentials := map[string]bool{}
	for i, n := range m.Nodes {
		if !identifier.MatchString(n.ID) || !identifier.MatchString(n.GroupID) || !identifier.MatchString(n.CredentialID) || n.Port < 1024 {
			return errors.New("invalid desired node")
		}
		if n.RelayAddress != "" && m.Template != TCPRelayTemplate && m.Template != TeamTemplate && m.Template != TeamSSTemplate {
			return errors.New("relay requires tcp-relay-v1 template")
		}
		if err := n.validateProtocol(); err != nil {
			return err
		}
		if m.Template == Template && n.ProtocolOptions.Normalized() != (ProtocolOptions{}).Normalized() {
			return errors.New("new protocol requires v2 template")
		}
		if ids[n.ID] || credentials[n.credential()] {
			return errors.New("duplicate desired node or credential")
		}
		ids[n.ID] = true
		credentials[n.credential()] = true
		ip, e := netip.ParseAddr(n.Listen)
		if e != nil || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return errors.New("invalid desired listener")
		}
		for _, other := range m.Nodes[:i] {
			if PortConflict(n, other) {
				return errors.New("desired listener collision")
			}
		}
	}
	return nil
}

// PortConflict conservatively treats IPv6 wildcard as dual stack. Independent
// instances share this test under the host port lock; only host namespace TCP exists.
func PortConflict(a, b Node) bool {
	if a.Port != b.Port {
		return false
	}
	x, e := netip.ParseAddr(a.Listen)
	y, f := netip.ParseAddr(b.Listen)
	if e != nil || f != nil {
		return true
	}
	return x == y || x.IsUnspecified() && (!x.Is4() || y.Is4()) || y.IsUnspecified() && (!y.Is4() || x.Is4())
}
func SemanticDiff(old, next Model, targetGroups []string) ([]string, error) {
	allowed := map[string]bool{}
	for _, id := range targetGroups {
		if !identifier.MatchString(id) {
			return nil, errors.New("invalid impact group")
		}
		allowed[id] = true
	}
	a := map[string]Node{}
	b := map[string]Node{}
	for _, n := range old.Nodes {
		n.ProtocolOptions = n.ProtocolOptions.Normalized()
		a[n.ID] = n
	}
	for _, n := range next.Nodes {
		n.ProtocolOptions = n.ProtocolOptions.Normalized()
		b[n.ID] = n
	}
	affected := map[string]bool{}
	for id, n := range a {
		v, ok := b[id]
		if !ok || !reflect.DeepEqual(n, v) {
			affected[n.GroupID] = true
			if ok {
				affected[v.GroupID] = true
			}
		}
	}
	for id, n := range b {
		if _, ok := a[id]; !ok {
			affected[n.GroupID] = true
		}
	}
	out := []string{}
	for g := range affected {
		if !allowed[g] {
			return nil, errors.New("unapproved cross-group semantic change")
		}
		out = append(out, g)
	}
	sort.Strings(out)
	return out, nil
}
// ValidatePreRenderedModel validates only host-level safety invariants (node IDs,
// non-overlapping unprivileged listen ports, and TLS certificate chains) when
// the panel supplies a pre-rendered sing-box configuration. Protocol-specific
// syntax is verified directly by `sing-box check` and isolated trial startup.
func ValidatePreRenderedModel(m Model, certs []Certificate, now time.Time) error {
	if len(m.Nodes) > 256 {
		return errors.New("unsupported model/template")
	}
	assets := map[string]Certificate{}
	for _, c := range certs {
		if !identifier.MatchString(c.ID) || len(c.CertificatePEM) > 1<<20 || len(c.PrivateKeyPEM) > 1<<20 || len(c.TrustPEM) > 1<<20 {
			return errors.New("invalid certificate asset")
		}
		if _, ok := assets[c.ID]; ok {
			return errors.New("duplicate certificate")
		}
		assets[c.ID] = c
	}
	seen := map[string]bool{}
	for i, n := range m.Nodes {
		if !identifier.MatchString(n.ID) || !identifier.MatchString(n.GroupID) || n.Port < 1024 {
			return errors.New("invalid node; only unprivileged ports supported")
		}
		if seen[n.ID] {
			return errors.New("duplicate node or credential")
		}
		seen[n.ID] = true
		ip, err := netip.ParseAddr(n.Listen)
		if err != nil || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return errors.New("invalid listen address")
		}
		for _, other := range m.Nodes[:i] {
			if PortConflict(n, other) {
				return errors.New("overlapping TCP listener")
			}
		}
		if !n.UsesCertificate() {
			continue
		}
		c, ok := assets[n.CertificateID]
		if !ok {
			return errors.New("missing certificate dependency")
		}
		pair, err := tls.X509KeyPair(c.CertificatePEM, c.PrivateKeyPEM)
		if err != nil {
			return errors.New("certificate and key mismatch")
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return errors.New("invalid leaf certificate")
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(c.TrustPEM) {
			return errors.New("explicit trusted CA required")
		}
		intermediates := x509.NewCertPool()
		for _, b := range pair.Certificate[1:] {
			parsed, e := x509.ParseCertificate(b)
			if e == nil {
				intermediates.AddCert(parsed)
			}
		}
		if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: n.ServerName, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return errors.New("TLS chain, SAN or validity rejected")
		}
	}
	return nil
}

func RenderPortable(m Model) ([]byte, error) {
	return Render(m, PortableVersionDir)
}

func Render(m Model, versionDir string) ([]byte, error) {
	nodes := append([]Node{}, m.Nodes...)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	inbounds := []any{}
	rules := []any{}
	for _, n := range nodes {
		tag := "node-" + n.ID
		inbounds = append(inbounds, inbound(n, versionDir))
		rules = append(rules, map[string]any{"inbound": []string{tag}, "action": "route", "outbound": "direct"})
	}
	return json.MarshalIndent(map[string]any{"log": map[string]any{"disabled": true}, "inbounds": inbounds, "outbounds": []any{map[string]string{"type": "direct", "tag": "direct"}}, "route": map[string]any{"rules": rules, "final": "direct"}}, "", "  ")
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func DecodeUUID(s string) ([]byte, error) {
	if !uuidPattern.MatchString(s) {
		return nil, errors.New("invalid UUID")
	}
	return hex.DecodeString(strings.ReplaceAll(s, "-", ""))
}
func CertificatesFromDir(dir string, m Model) ([]Certificate, error) {
	out := []Certificate{}
	seen := map[string]bool{}
	for _, n := range m.Nodes {
		if !n.UsesCertificate() {
			continue
		}
		if seen[n.CertificateID] {
			continue
		}
		seen[n.CertificateID] = true
		c := Certificate{ID: n.CertificateID}
		var e error
		c.CertificatePEM, e = readRegular(filepath.Join(dir, "tls-"+c.ID+".pem"))
		if e != nil {
			return nil, e
		}
		c.PrivateKeyPEM, e = readRegular(filepath.Join(dir, "key-"+c.ID+".pem"))
		if e != nil {
			return nil, e
		}
		c.TrustPEM, e = readRegular(filepath.Join(dir, "trust-"+c.ID+".pem"))
		if e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, nil
}
func CertificateSummary(c Certificate) (string, error) {
	block, _ := pem.Decode(c.CertificatePEM)
	if block == nil {
		return "", errors.New("invalid PEM")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("%s expires %s", digest(leaf.Raw), leaf.NotAfter.UTC().Format(time.RFC3339)), nil
}
