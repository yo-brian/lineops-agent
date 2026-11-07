//go:build linux

package agentbridge

import (
	"context"
	"errors"
	"io"
	"lineops-agent/internal/agentconfig"
	"lineops-agent/internal/release"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type ServerConfig struct {
	Paths              agentconfig.Paths
	Root, Socket       string
	AgentUID, AgentGID int
}

func ownedDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return &Error{Code: "invalid_managed_path"}
	}
	for p := path; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return &Error{Code: "unsafe_directory"}
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return &Error{Code: "root_ownership_required"}
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func validateSocket(path string) error {
	if e := ownedDirectory(filepath.Dir(path)); e != nil {
		return e
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 100 {
		return &Error{Code: "invalid_socket_path"}
	}
	info, e := os.Lstat(path)
	if e != nil || info.Mode()&os.ModeSocket == 0 || (info.Mode().Perm() != 0600 && info.Mode().Perm() != 0660) {
		return &Error{Code: "unsafe_socket"}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return &Error{Code: "root_socket_required"}
	}
	return nil
}
func registration(root, id string) error {
	if !identifier.MatchString(id) {
		return &Error{Code: "invalid_instance"}
	}
	dir := filepath.Join(root, id)
	if e := ownedDirectory(dir); e != nil {
		return e
	}
	for _, name := range []string{"runtime.json", "state.json"} {
		info, e := os.Lstat(filepath.Join(dir, name))
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
			return &Error{Code: "unsafe_registration"}
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return &Error{Code: "root_registration_required"}
		}
	}
	return nil
}

type peerListener struct {
	net.Listener
	uid uint32
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		conn, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			continue
		}
		raw, e := unixConn.SyscallConn()
		if e != nil {
			conn.Close()
			continue
		}
		var peer *syscall.Ucred
		var peerError error
		e = raw.Control(func(fd uintptr) {
			peer, peerError = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		})
		if e != nil || peerError != nil || peer == nil || (peer.Uid != l.uid && peer.Uid != 0) {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

// Serve accepts root or the single configured Agent UID. Supplementary group
// membership alone does not authorize a caller even if it can reach the socket.
func Serve(ctx context.Context, c ServerConfig) error {
	if os.Geteuid() != 0 {
		return &Error{Code: "root_executor_required"}
	}
	if c.AgentUID <= 0 || c.AgentGID <= 0 || uint64(c.AgentUID) >= 1<<32-1 || uint64(c.AgentGID) >= 1<<32-1 {
		return &Error{Code: "dedicated_agent_identity_required"}
	}
	if c.Socket == "" {
		c.Socket = DefaultSocket
	}
	if e := ownedDirectory(c.Root); e != nil {
		return e
	}
	if !filepath.IsAbs(c.Socket) || filepath.Clean(c.Socket) != c.Socket || len(c.Socket) > 100 {
		return &Error{Code: "invalid_socket_path"}
	}
	parent := filepath.Dir(c.Socket)
	if _, e := os.Lstat(parent); os.IsNotExist(e) {
		if e = os.Mkdir(parent, 0750); e != nil {
			return &Error{Code: "socket_directory_unavailable"}
		}
		if e = os.Chown(parent, 0, c.AgentGID); e != nil {
			return e
		}
	}
	if e := ownedDirectory(parent); e != nil {
		return e
	}
	info, e := os.Lstat(parent)
	if e != nil {
		return e
	}
	st := info.Sys().(*syscall.Stat_t)
	if int(st.Gid) != c.AgentGID || info.Mode().Perm()&0050 != 0050 {
		return &Error{Code: "socket_directory_group_mismatch"}
	}
	if _, e = os.Lstat(c.Socket); e == nil {
		return &Error{Code: "socket_already_exists"}
	} else if !os.IsNotExist(e) {
		return e
	}
	listener, e := net.Listen("unix", c.Socket)
	if e != nil {
		return &Error{Code: "socket_listen_failed"}
	}
	defer listener.Close()
	defer os.Remove(c.Socket)
	if e = os.Chown(c.Socket, 0, c.AgentGID); e != nil {
		return e
	}
	if e = os.Chmod(c.Socket, 0660); e != nil {
		return e
	}
	h := &handler{engine: release.Engine{Root: c.Root, Paths: c.Paths, Runtime: release.SystemdRuntime{}}, validateRegistration: func(id string) error { return registration(c.Root, id) }, active: make(chan struct{}, 4), verifying: make(chan struct{}, 2)}
	server := http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 7 * time.Minute, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0)}
	shutdown := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
			defer cancel()
			_ = server.Shutdown(stop)
		case <-shutdown:
		}
	}()
	e = server.Serve(peerListener{Listener: listener, uid: uint32(c.AgentUID)})
	if errors.Is(e, http.ErrServerClosed) {
		<-finished
		return nil
	}
	close(shutdown)
	<-finished
	return e
}

// ResolveAgent accepts only a numeric non-root UID/GID obtained by the root CLI.
func ParseIdentity(uid, gid string) (int, int, error) {
	u, e := strconv.Atoi(uid)
	if e != nil {
		return 0, 0, e
	}
	g, e := strconv.Atoi(gid)
	if e != nil {
		return 0, 0, e
	}
	if u <= 0 || g <= 0 || uint64(u) >= 1<<32-1 || uint64(g) >= 1<<32-1 {
		return 0, 0, &Error{Code: "dedicated_agent_identity_required"}
	}
	return u, g, nil
}

// NewInProcess initializes the release & lifecycle engine directly inside the
// single root-operated Agent process without requiring a separate lineops-executor
// daemon or Unix socket.
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
	if _, err := user.Lookup("lineops-singbox"); err != nil {
		_ = exec.Command("useradd", "--system", "--user-group", "--home-dir", "/nonexistent", "--no-create-home", "--shell", "/usr/sbin/nologin", "lineops-singbox").Run()
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
	if err := ownedDirectory(paths.InstancesDir); err != nil {
		return nil, err
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
