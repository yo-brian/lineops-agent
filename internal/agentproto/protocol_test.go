package agentproto

import (
	"lineop-agent/internal/release"
	"testing"
)

func TestInventoryTemplateBounds(t *testing.T) {
	templates := []string{release.Template, release.MultiProtocolTemplate, release.TCPRelayTemplate, release.TeamTemplate, release.TeamSSTemplate}
	for _, tc := range []struct {
		name      string
		executor  bool
		templates []string
		valid     bool
	}{
		{"legacy", true, templates[:4], true},
		{"ss", true, templates, true},
		{"oversized", true, append(append([]string{}, templates...), release.TeamSSTemplate), false},
		{"unknown", true, []string{"unknown-template"}, false},
		{"no-executor", false, templates, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := Inventory{ReleaseExecutor: tc.executor, ReleaseTemplates: tc.templates, ConfigurationState: "read_only", ProtocolState: "not_verified"}
			if i.Valid() != tc.valid {
				t.Fatalf("valid = %v, want %v", i.Valid(), tc.valid)
			}
		})
	}
}
