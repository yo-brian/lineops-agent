// Package agentconfig is the shared configuration contract for the Agent and
// privileged local tools. No YAML value is interpreted as shell input.
package agentconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
)

const DefaultFile = "/etc/lineops/config.yml"

type Paths struct {
	AgentBinDir    string `yaml:"agent_bin_dir" json:"agent_bin_dir"`
	AgentStateDir  string `yaml:"agent_state_dir" json:"agent_state_dir"`
	InstancesDir   string `yaml:"instances_dir" json:"instances_dir"`
	SingboxDir     string `yaml:"singbox_dir" json:"singbox_dir"`
	UpgradesDir    string `yaml:"upgrades_dir" json:"upgrades_dir"`
	LifecycleDir   string `yaml:"lifecycle_dir" json:"lifecycle_dir"`
	ExecutorSocket string `yaml:"executor_socket" json:"executor_socket"`
}
type Instance struct {
	ID      string   `yaml:"id" json:"id"`
	NodeIDs []string `yaml:"node_ids" json:"node_ids"`
}
type Binding struct {
	VPSID     string     `yaml:"vps_id" json:"vps_id"`
	NodeID    string     `yaml:"node_id,omitempty" json:"node_id,omitempty"`
	Instances []Instance `yaml:"instances" json:"instances"`
}
type Config struct {
	SchemaVersion int `yaml:"schema_version" json:"schema_version"`
	Panel         struct {
		URL    string `yaml:"url" json:"url"`
		APIKey string `yaml:"api_key,omitempty" json:"api_key,omitempty"`
		Token  string `yaml:"token,omitempty" json:"token,omitempty"`
		CAFile string `yaml:"ca_file" json:"ca_file"`
	} `yaml:"panel" json:"panel"`
	Enrollment struct {
		TokenEnv string `yaml:"token_env" json:"token_env"`
		Mode     string `yaml:"mode" json:"mode"`
	} `yaml:"enrollment" json:"enrollment"`
	Binding Binding `yaml:"binding" json:"binding"`
	Paths   Paths   `yaml:"paths" json:"paths"`
}

func NewPaths() Paths {
	return Paths{"/etc/lineops/bin", "/etc/lineops/state/agent", "/etc/lineops/instances", "/etc/lineops/sing-box", "/etc/lineops/backups/agent-upgrades", "/etc/lineops/state/lifecycle", "/run/lineops-executor/executor.sock"}
}

// ForRoot returns managed paths rooted at the given instances directory.
func ForRoot(root string) Paths {
	p := NewPaths()
	if root != "" && root != p.InstancesDir {
		p.InstancesDir = root
		p.LifecycleDir = path.Join(path.Dir(root), "lifecycle")
	}
	return p
}
func Default() Config {
	c := Config{SchemaVersion: 1, Paths: NewPaths()}
	c.Enrollment.Mode = "register"
	c.Enrollment.TokenEnv = "LINEOPS_ENROLLMENT_TOKEN"
	return c
}

var identifier = regexp.MustCompile(`^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var pathName = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

func safeAbsolute(p string) bool {
	return pathName.MatchString(p) && path.Clean(p) == p && p != "/" && !strings.Contains(p, "/../")
}
func (c Config) Validate() error {
	if c.SchemaVersion != 1 {
		return errors.New("unsupported config schema_version")
	}
	u, e := url.Parse(c.Panel.URL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("panel.url must be an HTTPS origin")
	}
	if c.Panel.CAFile != "" && !safeAbsolute(c.Panel.CAFile) {
		return errors.New("panel.ca_file must be a clean absolute path")
	}
	if c.Panel.APIKey != "" && (len(c.Panel.APIKey) > 256 || strings.ContainsAny(c.Panel.APIKey, " \t\r\n")) {
		return errors.New("invalid panel.api_key")
	}
	if c.Panel.Token != "" && (len(c.Panel.Token) > 256 || strings.ContainsAny(c.Panel.Token, " \t\r\n")) {
		return errors.New("invalid panel.token")
	}
	if c.Enrollment.Mode != "register" && c.Enrollment.Mode != "migrate" {
		return errors.New("invalid enrollment.mode")
	}
	if c.Enrollment.TokenEnv != "" && !envName.MatchString(c.Enrollment.TokenEnv) {
		return errors.New("invalid enrollment.token_env")
	}
	if c.Binding.VPSID != "" && !identifier.MatchString(c.Binding.VPSID) {
		return errors.New("invalid binding.vps_id")
	}
	if c.Binding.NodeID != "" && !identifier.MatchString(c.Binding.NodeID) {
		return errors.New("invalid binding.node_id")
	}
	if len(c.Binding.Instances) > 0 && c.Binding.VPSID == "" {
		return errors.New("binding.vps_id required for instance bindings")
	}
	seen := map[string]bool{}
	for _, i := range c.Binding.Instances {
		if !identifier.MatchString(i.ID) || seen[i.ID] {
			return errors.New("invalid or duplicate instance binding")
		}
		seen[i.ID] = true
		for _, id := range i.NodeIDs {
			if !identifier.MatchString(id) || seen[id] {
				return errors.New("invalid or duplicate node binding")
			}
			seen[id] = true
		}
	}
	dirs := []string{c.Paths.AgentBinDir, c.Paths.AgentStateDir, c.Paths.InstancesDir, c.Paths.SingboxDir, c.Paths.UpgradesDir, c.Paths.LifecycleDir}
	for _, p := range append(append([]string{}, dirs...), c.Paths.ExecutorSocket) {
		if !safeAbsolute(p) {
			return errors.New("paths must be clean absolute paths")
		}
	}
	for _, p := range dirs {
		if len(strings.Split(strings.Trim(p, "/"), "/")) < 2 || p == "/etc/lineops" || p == DefaultFile || strings.HasPrefix(p, DefaultFile+"/") {
			return errors.New("managed paths must be dedicated subdirectories")
		}
		if c.Panel.CAFile != "" && (c.Panel.CAFile == p || strings.HasPrefix(c.Panel.CAFile, p+"/")) {
			return errors.New("private CA must be outside managed binary and state directories")
		}
		for _, prefix := range []string{"/root/", "/home/", "/run/", "/tmp/", "/var/tmp/", "/proc/", "/sys/", "/dev/"} {
			if strings.HasPrefix(p, prefix) {
				return errors.New("managed paths cannot use home, temporary or virtual directories")
			}
		}
	}
	if c.Panel.CAFile == DefaultFile {
		return errors.New("private CA cannot overwrite config.yml")
	}
	for i, p := range dirs {
		for j, q := range dirs {
			if i != j && (p == q || strings.HasPrefix(p, q+"/")) {
				return errors.New("managed directories must not overlap")
			}
		}
	}
	if len(c.Paths.ExecutorSocket) > 100 || path.Dir(path.Dir(c.Paths.ExecutorSocket)) != "/run" {
		return errors.New("invalid executor socket path")
	}
	return nil
}
func Decode(r io.Reader) (Config, error) {
	c := Default()
	d := yaml.NewDecoder(io.LimitReader(r, 65537), yaml.Strict())
	if err := d.Decode(&c); err != nil {
		return Config{}, errors.New("invalid config YAML (unknown or duplicate fields are rejected)")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return Config{}, errors.New("config must contain one YAML document")
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}
func Load(path string) (Config, error) {
	if err := checkFile(path); err != nil {
		return Config{}, err
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > 65536 {
		return Config{}, errors.New("config exceeds size limit")
	}
	return Decode(f)
}
func (c Config) Redacted() Config {
	c.Panel.APIKey = ""
	c.Panel.Token = ""
	return c
}
func (c Config) Credential() string {
	if v := strings.TrimSpace(c.Panel.APIKey); v != "" {
		return v
	}
	if v := strings.TrimSpace(c.Panel.Token); v != "" {
		return v
	}
	if c.Enrollment.TokenEnv != "" {
		return strings.TrimSpace(os.Getenv(c.Enrollment.TokenEnv))
	}
	return ""
}
func (c Config) HasStaticCredential() bool {
	return strings.TrimSpace(c.Panel.APIKey) != "" || strings.TrimSpace(c.Panel.Token) != ""
}
func (c Config) JSON() ([]byte, error)     { return json.Marshal(c.Redacted()) }
func (p Paths) RecoveryBinary() string     { return path.Join(p.AgentBinDir, "lineops-recovery") }
func (p Paths) FRPDir() string {
	if p.SingboxDir != "" {
		return path.Join(path.Dir(p.SingboxDir), "frp")
	}
	return "/etc/lineops/frp"
}
func (c Config) CheckIdentity(vps string) error {
	if c.Binding.VPSID != "" && c.Binding.VPSID != vps {
		return fmt.Errorf("config VPS binding does not match registered identity")
	}
	return nil
}
