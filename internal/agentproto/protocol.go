package agentproto

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"lineops-agent/internal/release"
	"lineops-agent/internal/traffic"
	"time"
)

var Version = "0.10.1-dev"

type Lease struct {
	TaskID       string          `json:"task_id"`
	TargetID     string          `json:"target_id"`
	Kind         string          `json:"kind"`
	StepID       string          `json:"step_id"`
	Owner        string          `json:"-"`
	Fencing      int64           `json:"fencing"`
	Attempt      int             `json:"attempt"`
	InputVersion int64           `json:"input_version"`
	Deadline     time.Time       `json:"deadline"`
	Payload      json.RawMessage `json:"payload,omitempty"`
}

func Token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// Inventory contains observations, never native configuration or command lines.
type ServiceObservation struct {
	InstanceID string `json:"instance_id"`
	State      string `json:"state"`
}

type Inventory struct {
	SingBoxReconcile   bool                 `json:"singbox_reconcile"`
	SingBoxRestart     bool                 `json:"singbox_restart"`
	NodeTrafficErrors  map[string]string    `json:"node_traffic_errors,omitempty"`
	HostTraffic        []traffic.Sample     `json:"host_traffic,omitempty"`
	NodeTraffic        []traffic.Sample     `json:"node_traffic,omitempty"`
	TrafficError       string               `json:"traffic_error,omitempty"`
	Services           []ServiceObservation `json:"services,omitempty"`
	Hostname           string               `json:"hostname"`
	UptimeSeconds      uint64               `json:"uptime_seconds"`
	CPUCount           int                  `json:"cpu_count"`
	SingBoxLifecycle   bool                 `json:"singbox_lifecycle"`
	PreRenderedConfig  bool                 `json:"pre_rendered_config,omitempty"`
	AgentVersion       string               `json:"agent_version"`
	ReleaseExecutor    bool                 `json:"release_executor"`
	ReleaseTemplates   []string             `json:"release_templates,omitempty"`
	ManagedStates      []release.State      `json:"managed_states,omitempty"`
	OS                 string               `json:"os"`
	Architecture       string               `json:"architecture"`
	LoadAverage        string               `json:"load_average"`
	MemoryTotalKB      uint64               `json:"memory_total_kb"`
	MemoryAvailableKB  uint64               `json:"memory_available_kb"`
	DiskTotalBytes     uint64               `json:"disk_total_bytes"`
	DiskAvailableBytes uint64               `json:"disk_available_bytes"`
	ServiceName        string               `json:"service_name"`
	ServiceState       string               `json:"service_state"`
	BinaryPath         string               `json:"binary_path"`
	BinaryVersion      string               `json:"binary_version"`
	RunningMode        string               `json:"running_mode"`
	ConfigurationLoad  string               `json:"configuration_load"`
	ConfigurationPath  string               `json:"configuration_path"`
	ConfigurationHash  string               `json:"configuration_hash"`
	ConfigurationState string               `json:"configuration_state"`
	ProtocolState      string               `json:"protocol_state"`
	ErrorCode          string               `json:"error_code"`
	AgentLogs          []string             `json:"agent_logs,omitempty"`
	SingboxLogs        map[string][]string  `json:"singbox_logs,omitempty"`
}

func (i Inventory) Valid() bool {
	if len(i.AgentLogs) > 100 || len(i.SingboxLogs) > 100 {
		return false
	}
	for _, line := range i.AgentLogs {
		if len(line) > 1024 {
			return false
		}
	}
	for id, lines := range i.SingboxLogs {
		if len(id) != 36 || len(lines) > 100 {
			return false
		}
		for _, line := range lines {
			if len(line) > 1024 {
				return false
			}
		}
	}
	if len(i.NodeTrafficErrors) > 100 {
		return false
	}
	for id, code := range i.NodeTrafficErrors {
		if len(id) != 36 || len(code) > 100 {
			return false
		}
	}
	if len(i.HostTraffic) > 64 || len(i.NodeTraffic) > 3000 || len(i.TrafficError) > 100 {
		return false
	}
	for _, sample := range append(append([]traffic.Sample{}, i.HostTraffic...), i.NodeTraffic...) {
		if !sample.Valid() {
			return false
		}
	}
	if len(i.Services) > 100 {
		return false
	}
	for _, s := range i.Services {
		if len(s.InstanceID) != 36 || (s.State != "running" && s.State != "stopped" && s.State != "failed" && s.State != "not_installed" && s.State != "unknown") {
			return false
		}
	}
	if len(i.ReleaseTemplates) > 5 || (!i.ReleaseExecutor && len(i.ReleaseTemplates) > 0) {
		return false
	}
	for _, template := range i.ReleaseTemplates {
		if template != release.Template && template != release.MultiProtocolTemplate && template != release.TCPRelayTemplate && template != release.TeamTemplate && template != release.TeamSSTemplate {
			return false
		}
	}
	if len(i.ManagedStates) > 100 {
		return false
	}
	for _, s := range i.ManagedStates {
		if len(s.InstanceID) != 36 || len(s.Epoch) != 36 || s.Generation > 1_000_000_000_000 || s.Fencing > 1_000_000_000_000 || len(s.LastTaskID) > 64 || len(s.LastResult) > 32 || len(s.ErrorCode) > 100 || len(s.RequestDigest) > 64 || len(s.CurrentVersion) > 64 || len(s.VerifiedVersion) > 64 {
			return false
		}
	}
	return len(i.Hostname) <= 253 && i.CPUCount >= 0 && i.CPUCount <= 65536 && len(i.RunningMode) <= 32 && len(i.ConfigurationLoad) <= 64 && len(i.ConfigurationPath) <= 1024 && len(i.ConfigurationHash) <= 64 && len(i.AgentVersion) <= 80 && len(i.OS) <= 200 && len(i.Architecture) <= 40 && len(i.LoadAverage) <= 80 && len(i.ServiceName) <= 100 && len(i.ServiceState) <= 80 && len(i.BinaryPath) <= 1024 && len(i.BinaryVersion) <= 200 && len(i.ErrorCode) <= 100 && i.ConfigurationState == "read_only" && i.ProtocolState == "not_verified"
}
