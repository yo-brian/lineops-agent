//go:build linux

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
	"strconv"
	"strings"
	"time"
)

// Traffic reads only a registered instance's verified, loopback-only API.
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
		data, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", unit(runtime), "--property=InvocationID", "--property=ActiveState").Output()
		if err != nil {
			return "", errors.New("singbox_stats_service_inactive")
		}
		var source string
		active := false
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "InvocationID=") {
				source = strings.TrimPrefix(line, "InvocationID=")
			}
			if line == "ActiveState=active" {
				active = true
			}
		}
		if !active || !validInvocation(source) {
			return "", errors.New("singbox_stats_service_inactive")
		}
		return source, nil
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

func removeTrafficTable(ctx context.Context, id string) error {
	if !uuidPattern.MatchString(id) {
		return errors.New("invalid instance ID")
	}
	binary := "/usr/sbin/nft"
	if _, err := os.Stat(binary); err != nil {
		binary = "/sbin/nft"
	}
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		return nil
	}
	data, err := exec.CommandContext(ctx, binary, "-j", "list", "tables").Output()
	if err != nil {
		return err
	}
	var snapshot nftSnapshot
	if json.Unmarshal(data, &snapshot) != nil {
		return errors.New("invalid traffic tables")
	}
	table := "lo_traffic_" + strings.ReplaceAll(strings.ToLower(id), "-", "")
	for _, entry := range snapshot.NFTables {
		if entry.Table == nil || entry.Table.Name != table {
			continue
		}
		data, err = exec.CommandContext(ctx, binary, "-j", "list", "table", "inet", table).Output()
		if err != nil {
			return err
		}
		if _, _, err = decodeTraffic(data, table); err != nil {
			return err
		}
		return exec.CommandContext(ctx, binary, "delete", "table", "inet", table).Run()
	}
	return nil
}
