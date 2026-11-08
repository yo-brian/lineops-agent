package agentconfig

import (
	"strings"
	"testing"
)

func TestDecodeDefaults(t *testing.T) {
	c, e := Decode(strings.NewReader("schema_version: 1\npanel:\n  url: https://panel.example.com\n"))
	if e != nil || c.Paths != NewPaths() {
		t.Fatalf("defaults: %#v %v", c, e)
	}
}
func TestDecodeRejectsAmbiguousOrUnsafeConfiguration(t *testing.T) {
	base := "schema_version: 1\npanel:\n  url: https://panel.example.com\n"
	for name, suffix := range map[string]string{
		"unknown":            "unknown: true\n",
		"duplicate":          "schema_version: 1\n",
		"documents":          "---\nschema_version: 1\n",
		"relative":           "paths:\n  agent_bin_dir: relative\n",
		"traversal":          "paths:\n  agent_bin_dir: /etc/lineops/../bin\n",
		"overlap":            "paths:\n  agent_bin_dir: /etc/lineops/state\n",
		"system_dir":         "paths:\n  agent_bin_dir: /etc\n",
		"config_collision":   "paths:\n  agent_bin_dir: /etc/lineops/config.yml\n",
		"temporary_dir":      "paths:\n  agent_bin_dir: /tmp/lineops-bin\n",
		"socket_outside_run": "paths:\n  executor_socket: /etc/lineops/executor.sock\n",
		"bad_id":             "binding:\n  vps_id: invalid\n",
		"bad_node_id":        "binding:\n  node_id: invalid\n",
		"bad_api_key":        "panel:\n  url: https://panel.example.com\n  api_key: \"bad key\"\n",
		"shell_env":          "enrollment:\n  token_env: 'X; echo secret'\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := Decode(strings.NewReader(base + suffix)); e == nil {
				t.Fatal("accepted invalid config")
			}
		})
	}
}
func TestIdentityAndCustomPaths(t *testing.T) {
	c := Default()
	c.Panel.URL = "https://panel.example.com"
	c.Binding.VPSID = "11111111-1111-4111-8111-111111111111"
	if c.CheckIdentity("22222222-2222-4222-8222-222222222222") == nil {
		t.Fatal("foreign identity accepted")
	}
	if e := c.CheckIdentity(c.Binding.VPSID); e != nil {
		t.Fatal(e)
	}
	if ForRoot(NewPaths().InstancesDir).RecoveryBinary() != "/etc/lineops/bin/lineops-recovery" {
		t.Fatal("new recovery path")
	}
	if ForRoot("") != NewPaths() {
		t.Fatal("default ForRoot path regression")
	}
	direct, e := Decode(strings.NewReader("schema_version: 1\npanel:\n  url: https://panel.example.com\n  api_key: secret-api-key-123\nbinding:\n  node_id: 33333333-3333-4333-8333-333333333333\n"))
	if e != nil || direct.Credential() != "secret-api-key-123" || !direct.HasStaticCredential() || direct.Binding.NodeID != "33333333-3333-4333-8333-333333333333" {
		t.Fatalf("direct node/api_key config failed: %#v %v", direct, e)
	}
	rawJSON, e := direct.JSON()
	if e != nil || strings.Contains(string(rawJSON), "secret-api-key-123") {
		t.Fatalf("JSON leaked api_key: %s %v", string(rawJSON), e)
	}
}
