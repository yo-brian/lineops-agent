package release

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestTeamUsersRenderRevocationAndRecovery(t *testing.T) {
	n := Node{ID: "node", GroupID: "group", CredentialID: "legacy", UUID: "11111111-1111-4111-8111-111111111111", Port: 15443, Listen: "127.0.0.1", ServerName: "node.example", CertificateID: "cert", Users: []UserCredential{{ID: "alice", UUID: "22222222-2222-4222-8222-222222222222"}, {ID: "shared", UUID: "33333333-3333-4333-8333-333333333333"}}}
	m := Model{Schema: 1, Template: TeamTemplate, Nodes: []Node{n}}
	if e := validateShape(m); e != nil {
		t.Fatal(e)
	}
	raw, e := Render(m, "/tmp/test")
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	json.Unmarshal(raw, &v)
	inbounds := v["inbounds"].([]any)
	if len(inbounds) != 1 || len(inbounds[0].(map[string]any)["users"].([]any)) != 3 {
		t.Fatal("team users created extra listeners or missing identities")
	}
	policy := PolicySet{Epoch: "epoch", Groups: map[string]GroupPolicy{"group": {Version: 2, ExpiresAt: time.Now().Add(time.Hour), RevokedCredentialIDs: []string{"alice"}, LegacyCredentialsDisabled: true}}}
	effective, e := policy.Effective(m, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	users := effective.Nodes[0].AuthenticationNodes()
	if len(users) != 1 || users[0].CredentialID != "shared" {
		t.Fatal("revoke affected shared identity or retained old identity", users)
	}
	if len(m.Nodes[0].Users) != 2 || m.Nodes[0].LegacyDisabled {
		t.Fatal("effective policy mutated desired model")
	}
	old := m
	old.Nodes = []Node{n}
	old.Nodes[0].Users = nil
	old.Template = Template
	recovered, e := policy.Effective(old, time.Now())
	if e != nil || len(recovered.Nodes) != 0 {
		t.Fatal("rollback resurrected legacy credentials", e)
	}
	counters := map[string]uint64{"inbound>>>node-node>>>traffic>>>uplink": 100, "user>>>credential-shared>>>traffic>>>uplink": 25}
	samples := singboxSamples(effective, "instance", counters, time.Now())
	if len(samples) != 2 || samples[1].ResourceID != "shared" || samples[1].Upload != 25 {
		t.Fatal("identity stats missing", samples)
	}
	duplicate := m
	duplicate.Nodes = append([]Node{}, m.Nodes...)
	duplicate.Nodes[0].Users = append([]UserCredential{}, n.Users...)
	duplicate.Nodes[0].Users[1] = duplicate.Nodes[0].Users[0]
	if validateShape(duplicate) == nil {
		t.Fatal("duplicate independent credential accepted")
	}
	old = m
	old.Template = Template
	if validateShape(old) == nil {
		t.Fatal("old executors must not accept team models")
	}
	hy := Node{ID: "hy2-node", GroupID: "group", CredentialID: "hy2-legacy", Password: "hy2-root-password", Port: 15443, Listen: "127.0.0.1", ServerName: "node.example", CertificateID: "cert", ProtocolOptions: ProtocolOptions{Protocol: "hysteria2", Security: "tls", Transport: "quic"}, Users: []UserCredential{{ID: "alice", Password: "hy2-alice-password"}, {ID: "bob", Password: "hy2-bob-password"}}}
	hyModel := Model{Schema: 1, Template: ModelTemplate([]Node{hy}), Nodes: []Node{hy}}
	if hyModel.Template != TeamTemplate {
		t.Fatalf("expected TeamTemplate for Hysteria 2 team users, got %s", hyModel.Template)
	}
	if e := validateShape(hyModel); e != nil {
		t.Fatalf("valid Hysteria 2 team model rejected: %v", e)
	}
	hyInbound := inbound(hy, "/tmp/test")
	if len(hyInbound["users"].([]any)) != 3 {
		t.Fatalf("expected 3 Hysteria 2 users, got %+v", hyInbound["users"])
	}
}

func TestShadowsocksIndependentIdentities(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) {
			o := ProtocolOptions{Protocol: "shadowsocks", Method: method}
			root, _ := o.NewPassword()
			user, _ := o.NewPassword()
			n := Node{ID: "node", GroupID: "group", CredentialID: "legacy", Listen: "127.0.0.1", Port: 15443, ProtocolOptions: o, Password: root, SSMultiUser: true, Users: []UserCredential{{ID: "member", Password: user}}}
			m := Model{Schema: 1, Template: ModelTemplate([]Node{n}), Nodes: []Node{n}}
			if m.Template != TeamSSTemplate {
				t.Fatal("old template selected")
			}
			if e := validateShape(m); e != nil {
				t.Fatal(e)
			}
			in := inbound(n, "/unused")
			users := in["users"].([]any)
			if len(users) != 2 || users[1].(map[string]string)["password"] != user {
				t.Fatal("missing raw user password")
			}
			clients := n.AuthenticationNodes()
			if strings.HasPrefix(method, "2022-") {
				if in["password"] == root || strings.Contains(clients[1].Password, root) || clients[1].Password != o.SSServerKey(root)+":"+user {
					t.Fatal("server identity exposed legacy credential or invalid client password")
				}
			} else if clients[1].Password != user || clients[0].Password != root {
				t.Fatal("classic SS credentials changed")
			}
			// Disabling legacy on an earlier non-SS node must not downgrade the
			// template required by a later SS node during rollback/recovery.
			other := Node{ID: "other", GroupID: "other-group", CredentialID: "old-other", ProtocolOptions: ProtocolOptions{Protocol: "trojan"}}
			mixed := m
			mixed.Nodes = append([]Node{other}, m.Nodes...)
			policies := PolicySet{Groups: map[string]GroupPolicy{
				"other-group": {Version: 1, ExpiresAt: time.Now().Add(time.Hour), LegacyCredentialsDisabled: true},
				"group":       {Version: 1, ExpiresAt: time.Now().Add(time.Hour)},
			}}
			effective, err := policies.Effective(mixed, time.Now())
			if err != nil || effective.Template != TeamSSTemplate || len(effective.Nodes) != 1 {
				t.Fatal("recovery downgraded SS template", err)
			}
			m.Template = TeamTemplate
			if validateShape(m) == nil {
				t.Fatal("old executor template accepted SS users")
			}
		})
	}
}
