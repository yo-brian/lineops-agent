//go:build darwin

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

func darwinLabel(r RuntimeConfig) string {
	return "com.lineops.sing-box." + r.InstanceID
}

func darwinPlistPath(r RuntimeConfig) string {
	return filepath.Join("/Library/LaunchDaemons", darwinLabel(r)+".plist")
}

func serviceContent(r RuntimeConfig, dir string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>run</string>
		<string>-c</string>
		<string>%s/current/config.json</string>
	</array>
	<key>WorkingDirectory</key>
	<string>%s</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>StandardOutPath</key>
	<string>/var/log/lineops-sing-box-%s.log</string>
	<key>StandardErrorPath</key>
	<string>/var/log/lineops-sing-box-%s.log</string>
</dict>
</plist>
`, darwinLabel(r), r.Binary, dir, dir, r.InstanceID, r.InstanceID)
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
	if err != nil || len(out) == 0 {
		return errors.New("unverified sing-box binary version")
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

func unit(r RuntimeConfig) string { return darwinLabel(r) }

func verifyUnit(r RuntimeConfig, dir string) error {
	path := darwinPlistPath(r)
	b, e := readRegular(path)
	if e != nil || string(b) != serviceContent(r, dir) {
		return errors.New("managed service definition drift")
	}
	return nil
}

func (SystemdRuntime) Check(ctx context.Context, r RuntimeConfig, dir string) error {
	if err := runtimeValid(ctx, r); err != nil {
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
	return command(ctx, r.Binary, "check", "-c", filepath.Join(dir, "config.json"))
}

func (SystemdRuntime) Trial(ctx context.Context, r RuntimeConfig, dir string) error {
	return command(ctx, r.Binary, "check", "-c", filepath.Join(dir, "config.json"))
}

func (SystemdRuntime) Guard(ctx context.Context, r RuntimeConfig, root string, j Journal) error {
	delay := time.Until(j.Deadline)
	if delay <= 0 {
		return errors.New("publication deadline already expired")
	}
	go func() {
		time.Sleep(delay + time.Second)
		c, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		_ = command(c, r.RecoveryBinary, "recover", "--root", root, "--instance", r.InstanceID, "--task", j.TaskID, "--fencing", strconv.FormatUint(j.Fencing, 10))
	}()
	return nil
}

func (SystemdRuntime) Restart(ctx context.Context, r RuntimeConfig, dir string) error {
	if err := verifyUnit(r, dir); err != nil {
		return err
	}
	plist := darwinPlistPath(r)
	_ = exec.CommandContext(ctx, "/bin/launchctl", "bootout", "system", plist).Run()
	if err := exec.CommandContext(ctx, "/bin/launchctl", "bootstrap", "system", plist).Run(); err != nil {
		if err := exec.CommandContext(ctx, "/bin/launchctl", "load", "-w", plist).Run(); err != nil {
			return errors.New("launchd bootstrap failed")
		}
	}
	_ = exec.CommandContext(ctx, "/bin/launchctl", "kickstart", "-k", "system/"+darwinLabel(r)).Run()
	return nil
}

func (SystemdRuntime) Stop(ctx context.Context, r RuntimeConfig) error {
	plist := darwinPlistPath(r)
	_ = exec.CommandContext(ctx, "/bin/launchctl", "bootout", "system", plist).Run()
	_ = exec.CommandContext(ctx, "/bin/launchctl", "unload", plist).Run()
	return nil
}

func (SystemdRuntime) Healthy(ctx context.Context, r RuntimeConfig, dir string, m Model) error {
	if err := runtimeValid(ctx, r); err != nil {
		return err
	}
	if err := verifyUnit(r, filepath.Dir(filepath.Dir(dir))); err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+darwinLabel(r)).Output()
	if err != nil || !strings.Contains(string(out), "state = running") {
		return errors.New("managed process inactive")
	}
	return Probe(ctx, dir, m, r.Binary)
}

func ArmPolicy(ctx context.Context, root, id string) error {
	return nil
}

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
	servicePath := darwinPlistPath(r)
	if _, err = os.Lstat(servicePath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("service already exists; refusing takeover")
	}
	if err = os.MkdirAll(filepath.Join(dir, "versions"), 0750); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "runtime.json"), r); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "state.json"), State{InstanceID: r.InstanceID, Epoch: r.Epoch, LastResult: "unpublished"}); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(servicePath), 0755); err != nil {
		return err
	}
	return writeFile(servicePath, []byte(serviceContent(r, dir)), 0644)
}

func isolatedNetwork(string) (bool, error) { return true, nil }
func processAlive(p *os.Process) bool      { return p.Signal(syscall.Signal(0)) == nil }
