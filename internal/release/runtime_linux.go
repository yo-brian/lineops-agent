//go:build linux

package release

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type SystemdRuntime struct{}

var safeProgram = regexp.MustCompile(`^/[a-zA-Z0-9/_.-]+$`)

func command(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return errors.New("controlled system command failed")
	}
	return nil
}
func runtimeValid(ctx context.Context, r RuntimeConfig) error {
	if !identifier.MatchString(r.InstanceID) || !identifier.MatchString(r.Epoch) || !identifier.MatchString(r.ServiceUser) || r.ServiceUser == "root" || !SupportedSingboxVersion(r.BinaryVersion) {
		return errors.New("unsupported runtime registration")
	}
	for _, p := range []string{r.Binary, r.RecoveryBinary} {
		if err := protectedProgram(p); err != nil {
			return err
		}
	}
	b, err := readBinary(r.Binary)
	if err != nil || digest(b) != r.BinarySHA256 {
		return errors.New("registered sing-box binary drift")
	}
	out, err := exec.CommandContext(ctx, r.Binary, "version").Output()
	if err != nil || !outputHasVersion(out, r.BinaryVersion) {
		return errors.New("unverified sing-box binary version")
	}
	if r.TrafficAPI && !strings.Contains(string(out), "with_v2ray_api") {
		return errors.New("singbox_stats_build_required")
	}
	return nil
}
func protectedProgram(p string) error {
	if !safeProgram.MatchString(p) || filepath.Clean(p) != p {
		return errors.New("unsafe program path")
	}
	s, e := os.Lstat(p)
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0022 != 0 {
		return errors.New("program must be regular and not writable by group/others")
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return errors.New("program must be root owned")
	}
	for parent := filepath.Dir(p); ; parent = filepath.Dir(parent) {
		info, x := os.Lstat(parent)
		if x != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return errors.New("program parent must be a protected real directory")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("program parent must be root owned")
		}
		if parent == filepath.Dir(parent) {
			break
		}
	}
	return nil
}

func readBinary(path string) ([]byte, error) {
	s, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if s.Size() > 256<<20 {
		return nil, errors.New("binary too large")
	}
	return os.ReadFile(path)
}
func unit(r RuntimeConfig) string { return "lineops-sing-box-" + r.InstanceID + ".service" }
func (SystemdRuntime) Check(ctx context.Context, r RuntimeConfig, dir string) error {
	if err := runtimeValid(ctx, r); err != nil {
		return err
	}
	if err := grantVersionRead(r, dir); err != nil {
		return err
	}
	m, err := readModel(dir)
	if err != nil {
		return err
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, n := range m.Nodes {
		if n.RelayAddress == "" {
			continue
		}
		target, err := netip.ParseAddr(n.RelayAddress)
		if err != nil || !PublicRelayIP(n.RelayAddress) {
			return errors.New("invalid relay target")
		}
		for _, addr := range addresses {
			prefix, err := netip.ParsePrefix(addr.String())
			if err == nil && prefix.Addr().Unmap() == target.Unmap() {
				return errors.New("relay target belongs to entry VPS")
			}
		}
	}
	return command(ctx, "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--uid="+r.ServiceUser, "--property=NoNewPrivileges=yes", "--property=MemoryMax=256M", "--property=CPUQuota=100%", "--working-directory="+dir, r.Binary, "check", "-c", filepath.Join(dir, "config.json"))
}
func (SystemdRuntime) Trial(ctx context.Context, r RuntimeConfig, dir string) error {
	hostNetwork, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	return command(ctx, "/usr/bin/systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--uid="+r.ServiceUser, "--property=PrivateNetwork=yes", "--property=PrivateTmp=yes", "--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=yes", "--property=MemoryMax=256M", "--property=CPUQuota=100%", "--property=RuntimeMaxSec=25s", r.RecoveryBinary, "trial", "--binary", r.Binary, "--version-dir", dir, "--host-network", hostNetwork)
}
func (SystemdRuntime) Guard(ctx context.Context, r RuntimeConfig, root string, j Journal) error {
	if err := ArmPolicy(ctx, root, r.InstanceID); err != nil {
		return err
	}
	delay := time.Until(j.Deadline)
	if delay <= 0 {
		return errors.New("publication deadline already expired")
	}
	guard := fmt.Sprintf("lineops-recover-%s-%d-%d", r.InstanceID, j.Generation, j.Fencing)
	return command(ctx, "/usr/bin/systemd-run", "--quiet", "--collect", "--unit="+guard, "--on-active="+strconv.Itoa(int(delay.Seconds())+1)+"s", "--timer-property=AccuracySec=1s", r.RecoveryBinary, "recover", "--root", root, "--instance", r.InstanceID, "--task", j.TaskID, "--fencing", strconv.FormatUint(j.Fencing, 10))
}
func (SystemdRuntime) Restart(ctx context.Context, r RuntimeConfig, dir string) error {
	if err := verifyUnit(r, dir); err != nil {
		return err
	}
	// Publications must survive host reboot. The start gate still validates
	// authorization and interrupted publication state before running sing-box.
	if err := command(ctx, "/usr/bin/systemctl", "enable", unit(r)); err != nil {
		return err
	}
	return command(ctx, "/usr/bin/systemctl", "restart", unit(r))
}
func (SystemdRuntime) Stop(ctx context.Context, r RuntimeConfig) error {
	return command(ctx, "/usr/bin/systemctl", "stop", unit(r))
}
func (SystemdRuntime) Healthy(ctx context.Context, r RuntimeConfig, dir string, m Model) error {
	if err := runtimeValid(ctx, r); err != nil {
		return err
	}
	if err := verifyUnit(r, filepath.Dir(filepath.Dir(dir))); err != nil {
		return err
	}
	if err := command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", unit(r)); err != nil {
		return errors.New("managed process inactive")
	}
	return Probe(ctx, dir, m, r.Binary)
}
func serviceContent(r RuntimeConfig, dir string) string {
	return fmt.Sprintf("# Managed by Lineops; explicit local enrollment required.\n[Unit]\nDescription=Lineops managed sing-box %s\nAfter=network.target\n[Service]\nType=simple\nUser=%s\nWorkingDirectory=%s\nExecStartPre=+%s gate --root %s --instance %s\nExecStart=%s run -c %s/current/config.json\nExecStartPost=+%s arm-policy --root %s --instance %s\nRestart=no\nTimeoutStopSec=8\nKillMode=control-group\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nMemoryMax=512M\nCPUQuota=200%%\n[Install]\nWantedBy=multi-user.target\n", r.InstanceID, r.ServiceUser, dir, r.RecoveryBinary, filepath.Dir(dir), r.InstanceID, r.Binary, dir, r.RecoveryBinary, filepath.Dir(dir), r.InstanceID)
}

// ArmPolicy checks and starts the persistent, per-instance policy timer created
// by Initialize. It is independent of Agent/panel and runs from boot even when
// the managed service start gate rejects an expired or interrupted snapshot.
func ArmPolicy(ctx context.Context, root, id string) error {
	if os.Geteuid() != 0 {
		return errors.New("policy guard requires root")
	}
	e := Engine{Root: root, Runtime: SystemdRuntime{}}
	_, r, _, err := e.open(id)
	if err != nil {
		return err
	}
	if err = runtimeValid(ctx, r); err != nil {
		return err
	}
	name := "lineops-policy-" + id
	for suffix, expected := range map[string]string{".service": policyServiceContent(r, root), ".timer": policyTimerContent(r)} {
		b, x := readRegular(filepath.Join("/etc/systemd/system", name+suffix))
		if x != nil || string(b) != expected {
			return errors.New("independent policy guard definition drift")
		}
	}
	if err = command(ctx, "/usr/bin/systemctl", "enable", "--now", name+".timer"); err != nil {
		return errors.New("independent persistent policy guard could not be enabled")
	}
	return command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", name+".timer")
}
func policyServiceContent(r RuntimeConfig, root string) string {
	return fmt.Sprintf("# Managed by Lineops\n[Unit]\nDescription=Lineops independent policy and recovery %s\n[Service]\nType=oneshot\nUser=root\nExecStart=%s reconcile --root %s --instance %s\nTimeoutStartSec=6min\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=yes\nReadWritePaths=%s\n", r.InstanceID, r.RecoveryBinary, root, r.InstanceID, root)
}
func policyTimerContent(r RuntimeConfig) string {
	return fmt.Sprintf("# Managed by Lineops\n[Unit]\nDescription=Lineops independent authorization timer %s\n[Timer]\nOnBootSec=1s\nOnUnitInactiveSec=5s\nAccuracySec=1s\nUnit=lineops-policy-%s.service\n[Install]\nWantedBy=timers.target\n", r.InstanceID, r.InstanceID)
}
func verifyUnit(r RuntimeConfig, dir string) error {
	path := filepath.Join("/etc/systemd/system", unit(r))
	b, e := readRegular(path)
	if e != nil || string(b) != serviceContent(r, dir) {
		return errors.New("managed service definition drift")
	}
	out, e := exec.Command("/usr/bin/systemctl", "show", unit(r), "--property=DropInPaths", "--value").Output()
	if e != nil || strings.TrimSpace(string(out)) != "" {
		return errors.New("unexpected service drop-in")
	}
	return nil
}
func grantVersionRead(r RuntimeConfig, dir string) error {
	u, e := user.Lookup(r.ServiceUser)
	if e != nil {
		return e
	}
	gid, e := strconv.Atoi(u.Gid)
	if e != nil {
		return e
	}
	if e = os.Chown(dir, 0, gid); e != nil {
		return e
	}
	if e = os.Chmod(dir, 0750); e != nil {
		return e
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	for _, f := range entries {
		if f.IsDir() || f.Type()&os.ModeSymlink != 0 {
			return errors.New("unexpected dependency entry")
		}
		path := filepath.Join(dir, f.Name())
		if e = os.Chown(path, 0, gid); e != nil {
			return e
		}
		if e = os.Chmod(path, 0440); e != nil {
			return e
		}
	}
	return syncDir(dir)
}

// Initialize registers a new, empty managed instance. It never adopts or
// overwrites an existing sing-box service or unmanaged config directory.
func Initialize(ctx context.Context, root string, r RuntimeConfig) error {
	if os.Geteuid() != 0 {
		return errors.New("managed instance initialization requires root")
	}
	if !safeProgram.MatchString(root) || root == "/" {
		return errors.New("unsafe instance root")
	}
	if err := runtimeValid(ctx, r); err != nil {
		return err
	}
	if err := safeDir(root, true); err != nil {
		return err
	}
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("instance root must be root owned and protected")
	}
	if err := os.Chmod(root, 0711); err != nil {
		return err
	}
	unlock, err := acquire(ctx, filepath.Join(root, "host-ports.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	dir := filepath.Join(root, r.InstanceID)
	if _, err = os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
		return errors.New("instance already exists; explicit reconciliation required")
	}
	servicePath := filepath.Join("/etc/systemd/system", unit(r))
	if _, err = os.Lstat(servicePath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("service already exists; refusing takeover")
	}
	for _, suffix := range []string{".service", ".timer"} {
		if _, x := os.Lstat(filepath.Join("/etc/systemd/system", "lineops-policy-"+r.InstanceID+suffix)); !errors.Is(x, os.ErrNotExist) {
			return errors.New("policy unit already exists; refusing takeover")
		}
	}
	u, err := user.Lookup(r.ServiceUser)
	if err != nil {
		return errors.New("dedicated service user does not exist")
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0710); err != nil {
		return err
	}
	if err = os.Chmod(dir, 0710); err != nil {
		return err
	}
	if err = os.Chown(dir, 0, gid); err != nil {
		return err
	}
	vdir := filepath.Join(dir, "versions")
	if err = os.Mkdir(vdir, 0710); err != nil {
		return err
	}
	if err = os.Chmod(vdir, 0710); err != nil {
		return err
	}
	if err = os.Chown(vdir, 0, gid); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "runtime.json"), r); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "state.json"), State{InstanceID: r.InstanceID, Epoch: r.Epoch, LastResult: "unpublished"}); err != nil {
		return err
	}
	if err = writeFile(servicePath, []byte(serviceContent(r, dir)), 0644); err != nil {
		return err
	}
	for suffix, content := range map[string]string{".service": policyServiceContent(r, root), ".timer": policyTimerContent(r)} {
		if err = writeFile(filepath.Join("/etc/systemd/system", "lineops-policy-"+r.InstanceID+suffix), []byte(content), 0644); err != nil {
			return err
		}
	}
	if err = command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	return ArmPolicy(ctx, root, r.InstanceID)
}
func isolatedNetwork(hostNetwork string) (bool, error) {
	a, e := os.Readlink("/proc/self/ns/net")
	if e != nil {
		return false, e
	}
	if !regexp.MustCompile(`^net:\[[0-9]+\]$`).MatchString(hostNetwork) {
		return false, errors.New("host namespace witness missing")
	}
	return a != hostNetwork, nil
}
func processAlive(p *os.Process) bool { return p.Signal(syscall.Signal(0)) == nil }
