//go:build !linux

package agentbridge

import (
	"context"
	"lineop-agent/internal/agentconfig"
)

type ServerConfig struct {
	Paths              agentconfig.Paths
	Root, Socket       string
	AgentUID, AgentGID int
}

func validateSocket(string) error               { return &Error{Code: "linux_unix_socket_required"} }
func Serve(context.Context, ServerConfig) error { return &Error{Code: "linux_root_systemd_required"} }
func ParseIdentity(string, string) (int, int, error) {
	return 0, 0, &Error{Code: "linux_root_systemd_required"}
}
func NewInProcess(agentconfig.Paths) (*Client, error) {
	return nil, &Error{Code: "linux_root_systemd_required"}
}
