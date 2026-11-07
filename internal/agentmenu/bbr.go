package agentmenu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type command func(string, ...string) (string, error)
type tcpSettings struct {
	Congestion string `json:"congestion"`
	Qdisc      string `json:"qdisc"`
}

var kernelName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func output(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("%s: %s: %w", name, clean(string(b)), e)
	}
	return strings.TrimSpace(string(b)), nil
}
func setBBR(enable bool) error {
	return configureBBR("/run/lineops-agent-menu", enable, output)
}
func configureBBR(dir string, enable bool, cmd command) error {
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	info, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("BBR 备份目录权限异常")
	}
	lock := filepath.Join(dir, "lock")
	f, e := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return errors.New("BBR 设置正在执行或存在遗留锁，请核对本机菜单进程")
	}
	f.Close()
	defer os.Remove(lock)
	read := func() (tcpSettings, error) {
		a, e := cmd("sysctl", "-n", "net.ipv4.tcp_congestion_control")
		if e != nil {
			return tcpSettings{}, e
		}
		b, e := cmd("sysctl", "-n", "net.core.default_qdisc")
		if e != nil {
			return tcpSettings{}, e
		}
		if !kernelName.MatchString(a) || !kernelName.MatchString(b) {
			return tcpSettings{}, errors.New("内核返回的拥塞控制参数无效")
		}
		return tcpSettings{a, b}, nil
	}
	apply := func(v tcpSettings) error {
		if !kernelName.MatchString(v.Congestion) || !kernelName.MatchString(v.Qdisc) {
			return errors.New("备份参数无效")
		}
		if _, e := cmd("sysctl", "-w", "net.core.default_qdisc="+v.Qdisc); e != nil {
			return e
		}
		_, e := cmd("sysctl", "-w", "net.ipv4.tcp_congestion_control="+v.Congestion)
		return e
	}
	old, e := read()
	if e != nil {
		return e
	}
	backup := filepath.Join(dir, "before.json")
	target := tcpSettings{"bbr", "fq"}
	if enable {
		available, e := cmd("sysctl", "-n", "net.ipv4.tcp_available_congestion_control")
		if e != nil {
			return e
		}
		has := func(s string) bool {
			for _, v := range strings.Fields(s) {
				if v == "bbr" {
					return true
				}
			}
			return false
		}
		if !has(available) {
			if _, e = cmd("modprobe", "tcp_bbr"); e != nil {
				return e
			}
			available, e = cmd("sysctl", "-n", "net.ipv4.tcp_available_congestion_control")
			if e != nil {
				return e
			}
		}
		if !has(available) {
			return errors.New("当前内核不支持 BBR；未修改拥塞控制参数")
		}
		f, e := os.OpenFile(backup, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e == nil {
			e = json.NewEncoder(f).Encode(old)
			if e == nil {
				e = f.Sync()
			}
			closeErr := f.Close()
			if e != nil {
				return e
			}
			if closeErr != nil {
				return closeErr
			}
		} else if !os.IsExist(e) {
			return e
		} else {
			if _, e = readBackup(backup); e != nil {
				return e
			}
		}
	} else {
		target, e = readBackup(backup)
		if e != nil {
			return e
		}
	}
	if e = apply(target); e != nil {
		restoreErr := apply(old)
		return fmt.Errorf("设置失败：%v；恢复先前运行参数：%v", e, restoreErr)
	}
	actual, e := read()
	if e != nil || actual != target {
		restoreErr := apply(old)
		return fmt.Errorf("内核参数验证失败：%v；恢复先前运行参数：%v", e, restoreErr)
	}
	if !enable {
		if e = os.Remove(backup); e != nil {
			return e
		}
	}
	fmt.Printf("已设置：拥塞控制 %s，默认队列 %s（本次开机有效，新连接/新队列使用）\n", target.Congestion, target.Qdisc)
	return nil
}
func readBackup(path string) (tcpSettings, error) {
	var v tcpSettings
	info, e := os.Lstat(path)
	if e != nil {
		return v, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1024 {
		return v, errors.New("BBR 备份文件异常")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return v, e
	}
	e = json.Unmarshal(b, &v)
	if e == nil && (!kernelName.MatchString(v.Congestion) || !kernelName.MatchString(v.Qdisc)) {
		e = errors.New("BBR 备份参数无效")
	}
	return v, e
}
