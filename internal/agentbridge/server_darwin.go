//go:build darwin

package agentbridge

import (
	"context"
	"lineops-agent/internal/agentconfig"
	"lineops-agent/internal/release"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type ServerConfig struct {
	Paths              agentconfig.Paths
	Root, Socket       string
	AgentUID, AgentGID int
}

func validateSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return &Error{Code: "unsafe_socket"}
	}
	return nil
}

func registration(root, id string) error {
	if !identifier.MatchString(id) {
		return &Error{Code: "invalid_instance"}
	}
	dir := filepath.Join(root, id)
	for _, name := range []string{"runtime.json", "state.json"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() {
			return &Error{Code: "unsafe_registration"}
		}
	}
	return nil
}

func Serve(context.Context, ServerConfig) error {
	return &Error{Code: "use_in_process_executor_on_darwin"}
}

func ParseIdentity(uid, gid string) (int, int, error) {
	u, e := strconv.Atoi(uid)
	if e != nil {
		return 0, 0, e
	}
	g, e := strconv.Atoi(gid)
	if e != nil {
		return 0, 0, e
	}
	return u, g, nil
}

func NewInProcess(paths agentconfig.Paths) (*Client, error) {
	if os.Geteuid() != 0 {
		return nil, &Error{Code: "root_executor_required"}
	}
	if paths.InstancesDir == "" {
		paths = agentconfig.NewPaths()
	}
	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Dir(paths.InstancesDir), 0755},
		{paths.AgentBinDir, 0755},
		{paths.AgentStateDir, 0700},
		{paths.InstancesDir, 0711},
		{paths.SingboxDir, 0755},
		{paths.UpgradesDir, 0700},
		{paths.LifecycleDir, 0700},
	}
	for _, d := range dirs {
		if d.path == "" || d.path == "/" {
			continue
		}
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return nil, err
		}
		_ = os.Chown(d.path, 0, 0)
		_ = os.Chmod(d.path, d.mode)
	}
	recoveryBin := paths.RecoveryBinary()
	if _, err := os.Lstat(recoveryBin); os.IsNotExist(err) {
		if self, err := os.Executable(); err == nil {
			if realSelf, err := filepath.EvalSymlinks(self); err == nil {
				if os.Link(realSelf, recoveryBin) != nil {
					if data, err := os.ReadFile(realSelf); err == nil {
						_ = os.WriteFile(recoveryBin, data, 0755)
						_ = os.Chown(recoveryBin, 0, 0)
					}
				}
			}
		}
	}
	h := &handler{
		engine:               release.Engine{Root: paths.InstancesDir, Paths: paths, Runtime: release.SystemdRuntime{}},
		validateRegistration: func(id string) error { return registration(paths.InstancesDir, id) },
		active:               make(chan struct{}, 4),
		verifying:            make(chan struct{}, 2),
	}
	return &Client{
		http: &http.Client{
			Transport:     inProcessTransport{handler: h},
			Timeout:       7 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error { return &Error{Code: "redirect_forbidden"} },
		},
	}, nil
}
