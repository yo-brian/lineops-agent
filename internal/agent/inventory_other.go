//go:build !linux

package agent

import (
	"lineop-agent/internal/agentproto"
	"runtime"
)

func Inventory() agentproto.Inventory {
	return agentproto.Inventory{AgentVersion: agentproto.Version, OS: runtime.GOOS, Architecture: runtime.GOARCH, ServiceState: "unsupported_os", ConfigurationState: "read_only", ProtocolState: "not_verified", ErrorCode: "linux_required"}
}

func observeManagedServiceLogs(string) []string { return nil }
func observeManagedService(id string) agentproto.ServiceObservation {
	return agentproto.ServiceObservation{InstanceID: id, State: "unknown"}
}
