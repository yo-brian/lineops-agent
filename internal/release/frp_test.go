package release

import (
	"context"
	"lineops-agent/internal/agentconfig"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderFRPTOMLAndApply(t *testing.T) {
	srvTOML := RenderFRPServerTOML(7000, "secret-token-123456")
	if !strings.Contains(srvTOML, "bindPort = 7000") || !strings.Contains(srvTOML, `auth.token = "secret-token-123456"`) {
		t.Fatalf("unexpected frps.toml:\n%s", srvTOML)
	}

	cliTOML := RenderFRPClientTOML("203.0.113.10", 7000, "secret-token-123456", []FRPProxy{
		{Name: "au-mac-2083", Protocol: "tcp+udp", LocalIP: "127.0.0.1", LocalPort: 2083, RemotePort: 12083},
	})
	if !strings.Contains(cliTOML, `serverAddr = "203.0.113.10"`) ||
		!strings.Contains(cliTOML, `name = "au-mac-2083-tcp"`) ||
		!strings.Contains(cliTOML, `name = "au-mac-2083-udp"`) ||
		!strings.Contains(cliTOML, "localPort = 2083") ||
		!strings.Contains(cliTOML, "remotePort = 12083") {
		t.Fatalf("unexpected frpc.toml:\n%s", cliTOML)
	}

	tmp := t.TempDir()
	paths := agentconfig.Paths{
		SingboxDir: filepath.Join(tmp, "sing-box"),
	}
	req := FRPRequest{
		TaskID:  "11111111-1111-4111-8111-111111111111",
		Kind:    "uninstall_frp",
		Fencing: 5,
	}
	if !req.Valid() {
		t.Fatal("expected valid uninstall_frp request")
	}
	res := ApplyFRP(context.Background(), paths, req)
	if res.State != "succeeded" || !res.Valid() {
		t.Fatalf("unexpected ApplyFRP result: %+v", res)
	}
}
