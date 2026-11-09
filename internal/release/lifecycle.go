package release

import (
	"regexp"
	"time"
)

// Lifecycle commands contain identity and intent, never shell, paths or URLs.
const DefaultSingboxVersion = "1.14.4"

var SupportedSingboxVersions = []string{
	"1.14.4",
	"1.14.3",
	"1.14.2",
	"1.14.1",
	"1.14.0",
}

func SupportedSingboxVersion(v string) bool {
	for _, s := range SupportedSingboxVersions {
		if s == v {
			return true
		}
	}
	return false
}

type LifecycleRequest struct {
	TaskID        string `json:"task_id"`
	InstanceID    string `json:"instance_id"`
	Epoch         string `json:"epoch"`
	Kind          string `json:"kind"`
	Fencing       uint64 `json:"fencing"`
	TargetVersion string `json:"target_version,omitempty"`
}
type LifecycleResult struct {
	TaskID       string    `json:"task_id"`
	InstanceID   string    `json:"instance_id"`
	Epoch        string    `json:"epoch"`
	Kind         string    `json:"kind"`
	Fencing      uint64    `json:"fencing"`
	State        string    `json:"state"`
	Installed    bool      `json:"installed"`
	Version      string    `json:"version"`
	ServiceState string    `json:"service_state"`
	ErrorCode    string    `json:"error_code,omitempty"`
	FinishedAt   time.Time `json:"finished_at"`
}

var lifecycleID = regexp.MustCompile(`^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)

func (r LifecycleRequest) Valid() bool {
	return lifecycleID.MatchString(r.TaskID) && lifecycleID.MatchString(r.InstanceID) && lifecycleID.MatchString(r.Epoch) && r.Fencing > 0 && r.Fencing < 1<<63 && (r.Kind == "install_singbox" || r.Kind == "uninstall_singbox" || r.Kind == "restart_singbox") && (r.TargetVersion == "" || SupportedSingboxVersion(r.TargetVersion))
}
func (r LifecycleResult) Valid() bool {
	return (LifecycleRequest{TaskID: r.TaskID, InstanceID: r.InstanceID, Epoch: r.Epoch, Kind: r.Kind, Fencing: r.Fencing}).Valid() && (r.State == "succeeded" || r.State == "failed_manual" || r.State == "unknown") && len(r.ErrorCode) <= 100 && len(r.ServiceState) <= 40 && len(r.Version) <= 80 && !r.FinishedAt.IsZero()
}
