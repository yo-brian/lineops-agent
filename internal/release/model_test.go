package release

import (
	"testing"
	"time"
)

func TestSemanticIsolationAndAddressConflicts(t *testing.T) {
	a := Node{ID: "a", GroupID: "group-a", CredentialID: "credential-a", UUID: "11111111-1111-4111-8111-111111111111", Listen: "127.0.0.1", Port: 24001}
	b := Node{ID: "b", GroupID: "group-b", CredentialID: "credential-b", UUID: "22222222-2222-4222-8222-222222222222", Listen: "127.0.0.1", Port: 24002}
	old := Model{Schema: 1, Template: Template, Nodes: []Node{a, b}}
	next := old
	next.Nodes = []Node{a, b}
	next.Nodes[0].Port = 24003
	if _, e := SemanticDiff(old, next, []string{"group-a"}); e != nil {
		t.Fatal(e)
	}
	next.Nodes[1].UUID = a.UUID
	if _, e := SemanticDiff(old, next, []string{"group-a"}); e == nil {
		t.Fatal("cross-group credential change accepted")
	}
	a.Listen = "::"
	b.Port = a.Port
	if !PortConflict(a, b) {
		t.Fatal("IPv6 wildcard did not reserve dual-stack port")
	}
	a.Listen = "127.0.0.2"
	if PortConflict(a, b) {
		t.Fatal("distinct explicit addresses falsely overlap")
	}
}
func TestPoliciesDoNotResurrectCredentials(t *testing.T) {
	now := time.Now()
	old := PolicySet{Epoch: "epoch-1", Groups: map[string]GroupPolicy{"a": {Version: 2, ExpiresAt: now.Add(time.Hour), DisabledReasons: []string{"manual"}, RevokedCredentialIDs: []string{"old"}}}}
	if _, e := MergePolicies(old, PolicySet{Epoch: "epoch-1", Groups: map[string]GroupPolicy{"a": {Version: 1, ExpiresAt: now.Add(2 * time.Hour)}}}); e == nil {
		t.Fatal("accepted stale renewal")
	}
	p := old
	p.Groups = map[string]GroupPolicy{"a": {Version: 3, ExpiresAt: now.Add(2 * time.Hour), DisabledReasons: []string{"manual"}, RevokedCredentialIDs: []string{"old"}}}
	merged, e := MergePolicies(old, p)
	if e != nil {
		t.Fatal(e)
	}
	m := Model{Schema: 1, Template: Template, Nodes: []Node{{ID: "n", GroupID: "a", CredentialID: "old"}}}
	effective, e := merged.Effective(m, now)
	if e != nil || len(effective.Nodes) != 0 {
		t.Fatal("revoked credential restored")
	}
	if _, e = MergePolicies(old, PolicySet{Epoch: "restored-old-database", Groups: p.Groups}); e == nil {
		t.Fatal("old deployment epoch accepted")
	}
}
