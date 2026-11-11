//go:build darwin

package release

import (
	"context"
	"encoding/json"
	"errors"
	"lineops-agent/internal/traffic"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var darwinPIDPattern = regexp.MustCompile(`pid\s*=\s*([0-9]+)`)

func (e Engine) Traffic(ctx context.Context, id string) ([]traffic.Sample, error) {
	if !uuidPattern.MatchString(id) {
		return nil, errors.New("invalid instance ID")
	}
	unlock, err := e.locks(ctx, id)
	if err != nil {
		return nil, err
	}
	defer unlock()
	dir, runtime, state, err := e.open(id)
	if err != nil {
		return nil, err
	}
	if !runtime.TrafficAPI {
		return nil, errors.New("singbox_stats_upgrade_required")
	}
	if state.CurrentVersion == "" {
		return nil, errors.New("singbox_stats_publish_required")
	}
	model, _, err := verifyVersion(dir, state.CurrentVersion)
	if err != nil {
		return nil, err
	}
	target, err := os.Readlink(filepath.Join(dir, "current"))
	if err != nil || target != "versions/"+state.CurrentVersion {
		return nil, errors.New("traffic current version mismatch")
	}
	raw, err := readRegular(filepath.Join(dir, "versions", state.CurrentVersion, "config.json"))
	if err != nil {
		return nil, err
	}
	var config struct {
		Experimental struct {
			V2Ray struct {
				Listen string `json:"listen"`
			} `json:"v2ray_api"`
		} `json:"experimental"`
	}
	if json.Unmarshal(raw, &config) != nil || config.Experimental.V2Ray.Listen == "" {
		return nil, errors.New("singbox_stats_publish_required")
	}
	listener := trafficListener(id, model)
	endpoint := net.JoinHostPort(listener.Listen, strconv.Itoa(int(listener.Port)))
	if config.Experimental.V2Ray.Listen != endpoint {
		return nil, errors.New("singbox_stats_invalid")
	}
	invocation := func() (string, error) {
		out, err := exec.CommandContext(ctx, "/bin/launchctl", "print", "system/"+darwinLabel(runtime)).Output()
		if err != nil || !strings.Contains(string(out), "state = running") {
			return "", errors.New("singbox_stats_service_inactive")
		}
		m := darwinPIDPattern.FindStringSubmatch(string(out))
		pid := "1"
		if len(m) == 2 {
			pid = m[1]
		}
		return strings.TrimSpace(bootID()) + "-pid-" + pid, nil
	}
	before, err := invocation()
	if err != nil {
		return nil, err
	}
	counters, err := querySingboxTraffic(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	after, err := invocation()
	if err != nil || before != after {
		return nil, errors.New("singbox_stats_service_inactive")
	}
	return singboxSamples(model, before, counters, time.Now().UTC()), nil
}
