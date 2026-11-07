//go:build linux

package release

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// This verifies failure handling only; real process and protocol acceptance is
// covered separately by TestRealLinuxSharedReleaseAndIndependentRecovery.
func TestUnreadableJournalBlocksOfflineStartAndScan(t *testing.T) {
	root := t.TempDir()
	id := "journal-test"
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(filepath.Join(dir, "versions"), 0700); err != nil {
		t.Fatal(err)
	}
	r := RuntimeConfig{InstanceID: id, Epoch: "test-epoch"}
	s := State{InstanceID: id, Epoch: r.Epoch, Generation: 1, Fencing: 1, CurrentVersion: "v-1-1", VerifiedVersion: "v-1-1", LastResult: "succeeded"}
	p := PolicySet{Epoch: r.Epoch, Groups: map[string]GroupPolicy{}}
	for name, value := range map[string]any{"runtime.json": r, "state.json": s, "policies.json": p} {
		if err := writeJSON(filepath.Join(dir, name), value); err != nil {
			t.Fatal(err)
		}
	}
	m := Model{Schema: 1, Template: Template, Nodes: []Node{}}
	if _, err := freezeVersion(dir, s.CurrentVersion, m, m, nil); err != nil {
		t.Fatal(err)
	}
	if err := switchCurrent(dir, s.CurrentVersion); err != nil {
		t.Fatal(err)
	}
	e := Engine{Root: root, Runtime: SystemdRuntime{}}
	if err := e.StartGate(id); err != nil {
		t.Fatalf("valid empty instance startup gate: %v", err)
	}
	// A normal publication must pass its own startup gate; after a boot change
	// the same pending candidate must still be blocked until recovery.
	j := Journal{State: "switched", CandidateVersion: s.CurrentVersion, BootID: bootID()}
	if err := writeJSON(filepath.Join(dir, "journal.json"), j); err != nil {
		t.Fatal(err)
	}
	if err := e.StartGate(id); err != nil {
		t.Fatalf("same-boot publication blocked: %v", err)
	}
	j.BootID = "previous-boot"
	if err := writeJSON(filepath.Join(dir, "journal.json"), j); err != nil {
		t.Fatal(err)
	}
	if err := e.StartGate(id); err == nil || err.Error() != "startup blocked until interrupted publication is recovered" {
		t.Fatalf("interrupted publication startup result: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "journal.json"), []byte(`{"state":`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := e.StartGate(id); err == nil {
		t.Fatal("startup accepted an unreadable journal")
	}
	if got := e.Scan(context.Background())[id]; got != "journal_unreadable" {
		t.Fatalf("scan treated an unreadable journal as reconciled: %q", got)
	}
	if _, err := e.UpdatePolicies(context.Background(), id, p); err == nil {
		t.Fatal("policy reconciliation accepted an unreadable journal")
	}
	after, err := e.Status(id)
	if err != nil || after != s {
		t.Fatalf("failed journal handling changed persisted state: %+v, %v", after, err)
	}
}
