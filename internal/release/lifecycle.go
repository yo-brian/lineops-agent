package release

import (
	"regexp"
	"time"
)

// Lifecycle commands contain identity and intent, never shell, paths or URLs.
type LifecycleRequest struct {
	TaskID     string `json:"task_id"`
	InstanceID string `json:"instance_id"`
	Epoch      string `json:"epoch"`
	Kind       string `json:"kind"`
	Fencing    uint64 `json:"fencing"`
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
	return lifecycleID.MatchString(r.TaskID) && lifecycleID.MatchString(r.InstanceID) && lifecycleID.MatchString(r.Epoch) && r.Fencing > 0 && r.Fencing < 1<<63 && (r.Kind == "install_singbox" || r.Kind == "uninstall_singbox" || r.Kind == "restart_singbox")
}
func (r LifecycleResult) Valid() bool {
	return (LifecycleRequest{r.TaskID, r.InstanceID, r.Epoch, r.Kind, r.Fencing}).Valid() && (r.State == "succeeded" || r.State == "failed_manual" || r.State == "unknown") && len(r.ErrorCode) <= 100 && len(r.ServiceState) <= 40 && len(r.Version) <= 80 && !r.FinishedAt.IsZero()
}
