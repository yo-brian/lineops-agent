package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"lineops-agent/internal/agentbridge"
	"lineops-agent/internal/agentconfig"
	"lineops-agent/internal/agentproto"
	"lineops-agent/internal/release"
	"lineops-agent/internal/traffic"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Client struct {
	BaseURL, StateDir             string
	HTTP                          *http.Client
	identity                      identity
	binding                       agentconfig.Binding
	EnrollmentMode                string
	StaticCredential              string
	Executor                      *agentbridge.Client
	heartbeatGzip, heartbeatDelta bool
	acknowledgedTraffic           []traffic.Sample
	cachedInstanceIDs             []string
	cachedInstancesValid          bool
}
type identity struct {
	Token   string `json:"identity_token"`
	AgentID string `json:"agent_id"`
	VPSID   string `json:"vps_id"`
	Version int64  `json:"identity_version"`
}

func New(panel, stateDir, caFile string) (*Client, error) {
	u, err := url.Parse(panel)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, errors.New("panel must be an HTTPS origin")
	}
	if !filepath.IsAbs(stateDir) {
		return nil, errors.New("state directory must be absolute")
	}
	stateDir = filepath.Clean(stateDir)
	// Reject symbolic links in existing parents before creating protected state.
	for path := filepath.Clean(stateDir); ; path = filepath.Dir(path) {
		info, e := os.Lstat(path)
		if e == nil && runtime.GOOS == "darwin" && (path == "/var" || path == "/etc" || path == "/tmp") {
			info, e = os.Stat(path)
		}
		if e == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("state path contains symbolic link")
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	if err = os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	if err = os.Chmod(stateDir, 0700); err != nil {
		return nil, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if caFile != "" {
		pem, e := os.ReadFile(caFile)
		if e != nil {
			return nil, e
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid CA file")
		}
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, Proxy: nil, ResponseHeaderTimeout: 20 * time.Second}
	cl := &Client{BaseURL: panel, StateDir: stateDir, HTTP: &http.Client{Transport: transport, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect rejected") }}}
	path := filepath.Join(stateDir, "identity.json")
	if info, e := os.Lstat(path); e == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("unsafe identity file")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		if json.Unmarshal(b, &cl.identity) != nil {
			return nil, errors.New("invalid identity state")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	return cl, nil
}
func (c *Client) request(ctx context.Context, method, path string, input, out any) (int, error) {
	status, err := c.doRequest(ctx, method, path, input, out)
	if status == 401 && path != "/register" && c.StaticCredential != "" {
		c.identity = identity{}
		_ = c.removeState("identity.json")
		_ = c.removeState("enrollment-pending.json")
		if enrollErr := c.Enroll(ctx, c.StaticCredential); enrollErr == nil {
			return c.doRequest(ctx, method, path, input, out)
		}
	}
	return status, err
}
func (c *Client) doRequest(ctx context.Context, method, path string, input, out any) (int, error) {
	var reader io.Reader
	compressed := false
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return 0, err
		}
		if path == "/heartbeat" && c.heartbeatGzip && len(data) >= 1024 {
			var packed bytes.Buffer
			writer, _ := gzip.NewWriterLevel(&packed, gzip.BestSpeed)
			_, _ = writer.Write(data)
			_ = writer.Close()
			if packed.Len() < len(data) {
				data = packed.Bytes()
				compressed = true
			}
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+"/api/v1/agent"+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if vpsID := c.binding.VPSID; vpsID != "" {
		req.Header.Set("X-LineOps-VPS-ID", vpsID)
	} else if c.identity.VPSID != "" {
		req.Header.Set("X-LineOps-VPS-ID", c.identity.VPSID)
	}
	if c.binding.NodeID != "" {
		req.Header.Set("X-LineOps-Node-ID", c.binding.NodeID)
	}
	if c.identity.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.identity.Token)
	} else if c.StaticCredential != "" && path != "/register" {
		req.Header.Set("Authorization", "Bearer "+c.StaticCredential)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, errors.New("panel TLS connection failed")
	}
	defer func() {
		// Small acknowledgements (including heartbeats) must reach EOF before
		// Close so the transport can reuse TLS connections. Bound unexpected
		// response tails; oversized or interrupted bodies simply lose reuse.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("panel rejected operation (HTTP %d); inspect panel task", resp.StatusCode)
	}
	if resp.StatusCode == 204 {
		return 204, nil
	}
	if out != nil {
		err = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
		if err != nil {
			return resp.StatusCode, errors.New("invalid bounded panel response")
		}
	}
	return resp.StatusCode, nil
}
func (c *Client) save(name string, value any) error {
	if filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
		return errors.New("invalid state file name")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.StateDir, ".pending-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), filepath.Join(c.StateDir, name)); err != nil {
		return err
	}
	return syncDirectory(c.StateDir)
}
func (c *Client) Enroll(ctx context.Context, token string) error {
	if c.identity.Token != "" {
		return errors.New("identity already present; revoke/re-enroll explicitly")
	}
	pending := struct {
		Registration   string `json:"registration_token"`
		Token          string `json:"identity_token"`
		ExpectedVPSID  string `json:"expected_vps_id,omitempty"`
		ExpectedNodeID string `json:"expected_node_id,omitempty"`
		Mode           string `json:"mode,omitempty"`
	}{strings.TrimSpace(strings.TrimPrefix(token, "\uFEFF")), agentproto.Token(), c.binding.VPSID, c.binding.NodeID, c.EnrollmentMode}
	if data, err := c.readState("enrollment-pending.json"); err == nil {
		if json.Unmarshal(data, &pending) != nil {
			return errors.New("invalid pending registration")
		}
		if strings.TrimSpace(strings.TrimPrefix(token, "\uFEFF")) != pending.Registration {
			return errors.New("pending enrollment uses a different token; explicitly remove pending state after revoking it")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := c.save("enrollment-pending.json", pending); err != nil {
		return err
	}
	var result identity
	if _, err := c.request(ctx, "POST", "/register", pending, &result); err != nil {
		return err
	}
	if len(result.Token) != 43 {
		return errors.New("invalid identity reply")
	}
	if c.binding.VPSID != "" && result.VPSID != c.binding.VPSID {
		return errors.New("registered identity does not match configured VPS")
	}
	if c.binding.VPSID == "" && c.binding.NodeID != "" {
		c.binding.VPSID = result.VPSID
	}
	if err := c.save("identity.json", result); err != nil {
		return errors.New("registration may have succeeded; local identity persistence failed; revoke and re-enroll")
	}
	c.identity = result
	return c.removeState("enrollment-pending.json")
}
func (c *Client) EnsureEnrolled(ctx context.Context) error {
	if c.identity.Token == "" && c.StaticCredential != "" {
		return c.Enroll(ctx, c.StaticCredential)
	}
	return nil
}
func (c *Client) Heartbeat(ctx context.Context) error {
	if err := c.EnsureEnrolled(ctx); err != nil {
		return err
	}
	if err := c.ResumeRotation(ctx); err != nil {
		return err
	}
	if c.identity.Token == "" && c.StaticCredential == "" {
		return errors.New("agent not enrolled")
	}
	i := Inventory()
	i.HostTraffic = hostTraffic()
	trafficSupported := false
	if c.Executor != nil {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		templates, capabilities, err := c.Executor.Capabilities(probeCtx)
		for _, capability := range capabilities {
			if capability == "singbox_reconcile_v1" {
				i.SingBoxReconcile = err == nil
			}
			if capability == "node_traffic_v2" {
				trafficSupported = true
			}
			if capability == "singbox_restart_v1" {
				i.SingBoxRestart = err == nil
			}
			if capability == "singbox_lifecycle_v1" {
				i.SingBoxLifecycle = true
			}
			if capability == "pre_rendered_config_v1" {
				i.PreRenderedConfig = err == nil
			}
		}
		i.ReleaseExecutor = err == nil
		if i.ReleaseExecutor {
			i.ReleaseTemplates = templates
			i.FRPLifecycle = true
			frpStatus := release.ObserveFRP(agentconfig.NewPaths())
			i.FRPStatus = &frpStatus
		}
		cancel()
		if i.ReleaseExecutor {
			return c.visitInstancePages(ctx, func(ids []string, partial bool) error {
				page := i
				page.Services = nil
				page.SingboxLogs = nil
				page.ManagedStates = nil
				page.NodeTraffic = nil
				page.NodeTrafficErrors = nil
				var trafficObserved []string
				for _, instanceID := range ids {
					if trafficSupported {
						trafficCtx, trafficCancel := context.WithTimeout(ctx, 5*time.Second)
						samples, trafficErr := c.Executor.Traffic(trafficCtx, instanceID)
						trafficCancel()
						if trafficErr == nil && len(page.NodeTraffic)+len(samples) <= 3000 {
							page.NodeTraffic = append(page.NodeTraffic, samples...)
							trafficObserved = append(trafficObserved, instanceID)
						} else {
							page.TrafficError = "node_traffic_unavailable"
							var bridgeError *agentbridge.Error
							if errors.As(trafficErr, &bridgeError) {
								page.TrafficError = bridgeError.Code
							}
							if page.NodeTrafficErrors == nil {
								page.NodeTrafficErrors = map[string]string{}
							}
							page.NodeTrafficErrors[instanceID] = page.TrafficError
						}
					}
					page.Services = append(page.Services, observeManagedService(instanceID))
					probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
					state, e := c.Executor.Status(probeCtx, instanceID)
					cancel()
					if e == nil {
						page.ManagedStates = append(page.ManagedStates, state)
					}
				}
				return c.sendHeartbeatPage(ctx, page, partial, trafficObserved...)
			})
		}
	}
	return c.sendHeartbeat(ctx, i)
}

// New panels advertise partial observations alongside cursor pagination. Older
// panels still yield one bounded page and receive the unchanged full heartbeat.
func (c *Client) visitInstancePages(ctx context.Context, visit func([]string, bool) error) error {
	if c.cachedInstancesValid {
		ids := append([]string(nil), c.cachedInstanceIDs...)
		return visit(ids, true)
	}
	after := ""
	for {
		path := "/instances"
		if after != "" {
			path += "?after=" + url.QueryEscape(after)
		}
		var result struct {
			Items []struct {
				ID string `json:"id"`
			} `json:"items"`
			HasMore bool   `json:"has_more"`
			Next    string `json:"next_cursor"`
			Mode    string `json:"observation_mode"`
		}
		if _, err := c.request(ctx, "GET", path, nil, &result); err != nil {
			return err
		}
		if len(result.Items) > 100 {
			return errors.New("managed instance page exceeds Agent bound")
		}
		partial := result.Mode == agentproto.InstanceObservations
		ids := make([]string, len(result.Items))
		for index, item := range result.Items {
			if len(item.ID) != 36 || strings.ContainsAny(item.ID, "/\\.") || (partial && ((after != "" && item.ID <= after) || (index > 0 && item.ID <= ids[index-1]))) {
				return errors.New("invalid managed instance page")
			}
			ids[index] = item.ID
		}
		if result.HasMore && (!partial || len(ids) == 0 || result.Next != ids[len(ids)-1]) {
			return errors.New("invalid managed instance pagination")
		}
		if err := visit(ids, partial); err != nil {
			return err
		}
		if !result.HasMore {
			return nil
		}
		after = result.Next
	}
}

type receipt struct {
	TaskID               string                        `json:"task_id"`
	Fencing              int64                         `json:"fencing"`
	Inventory            agentproto.Inventory          `json:"inventory"`
	ExecutionError       string                        `json:"execution_error,omitempty"`
	Lifecycle            *release.LifecycleResult      `json:"lifecycle,omitempty"`
	LifecycleObservation *release.LifecycleObservation `json:"lifecycle_observation,omitempty"`
	Release              *release.State                `json:"release,omitempty"`
	FRP                  *release.FRPResult            `json:"frp,omitempty"`
}

func (c *Client) Poll(ctx context.Context) error {
	if err := c.EnsureEnrolled(ctx); err != nil {
		return err
	}
	if err := c.reconcileLifecycle(ctx); err != nil {
		return err
	}
	if err := c.reconcileInflight(ctx); err != nil {
		return err
	}
	if err := c.replayReceipts(ctx); err != nil {
		return err
	}
	var cmd agentproto.Lease
	status, err := c.request(ctx, "GET", "/commands", nil, &cmd)
	if err != nil || status == 204 {
		return err
	}
	if (cmd.Kind != "agent_logs" && cmd.Kind != "inventory" && cmd.Kind != "release" && cmd.Kind != "release_reconcile" && cmd.Kind != "singbox_reconcile" && cmd.Kind != "install_singbox" && cmd.Kind != "uninstall_singbox" && cmd.Kind != "restart_singbox" && cmd.Kind != "configure_frp" && cmd.Kind != "restart_frp" && cmd.Kind != "uninstall_frp") || len(cmd.TaskID) != 36 || strings.ContainsAny(cmd.TaskID, "/\\.") || cmd.Fencing < 1 || time.Now().After(cmd.Deadline) {
		return errors.New("unsupported or expired command")
	}
	if cmd.Kind == "agent_logs" {
		_, err := c.request(ctx, "POST", "/logs", map[string]any{"agent_logs": CollectAgentLogs()}, nil)
		return err
	}
	if cmd.Kind == "configure_frp" || cmd.Kind == "restart_frp" || cmd.Kind == "uninstall_frp" {
		return c.executeFRP(ctx, cmd)
	}
	if cmd.Kind == "singbox_reconcile" {
		return c.executeLifecycleReconcile(ctx, cmd)
	}
	if cmd.Kind == "install_singbox" || cmd.Kind == "uninstall_singbox" || cmd.Kind == "restart_singbox" {
		return c.executeLifecycle(ctx, cmd)
	}
	if cmd.Kind == "release" || cmd.Kind == "release_reconcile" {
		return c.executeRelease(ctx, cmd)
	}
	name := fmt.Sprintf("receipt-%s-%d.json", cmd.TaskID, cmd.Fencing)
	var result receipt
	path := filepath.Join(c.StateDir, name)
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() {
			return errors.New("unsafe receipt path")
		}
		data, e := os.ReadFile(path)
		if e != nil || json.Unmarshal(data, &result) != nil {
			return errors.New("receipt requires manual reconciliation")
		}
	} else if errors.Is(e, os.ErrNotExist) {
		result = receipt{TaskID: cmd.TaskID, Fencing: cmd.Fencing, Inventory: Inventory()}
		if err = c.save(name, result); err != nil {
			return err
		}
	} else {
		return e
	}
	if result.TaskID != cmd.TaskID || result.Fencing != cmd.Fencing {
		return errors.New("receipt identity mismatch")
	}
	return c.submitReceipt(ctx, name, result)
}

func (c *Client) readState(name string) ([]byte, error) {
	path := filepath.Join(c.StateDir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("unsafe or oversized state file")
	}
	return os.ReadFile(path)
}
func (c *Client) removeState(name string) error {
	if err := os.Remove(filepath.Join(c.StateDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(c.StateDir)
}

// The candidate is durable before prepare. Confirmation uses the candidate
// bearer and can be repeated after either HTTP response or local save is lost.
func (c *Client) Rotate(ctx context.Context) error {
	if c.identity.Token == "" {
		return errors.New("agent not enrolled")
	}
	if _, err := c.readState("rotation-pending.json"); errors.Is(err, os.ErrNotExist) {
		candidate := c.identity
		candidate.Token = agentproto.Token()
		candidate.Version++
		if err = c.save("rotation-pending.json", candidate); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return c.ResumeRotation(ctx)
}
func (c *Client) ResumeRotation(ctx context.Context) error {
	data, err := c.readState("rotation-pending.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var candidate identity
	if json.Unmarshal(data, &candidate) != nil || len(candidate.Token) != 43 || candidate.AgentID != c.identity.AgentID {
		return errors.New("invalid pending identity")
	}
	probe := *c
	probe.StaticCredential = ""
	probe.identity = candidate
	var confirmed identity
	status, err := probe.request(ctx, "POST", "/rotate/confirm", struct{}{}, &confirmed)
	if err != nil && status == 401 {
		if _, err = c.request(ctx, "POST", "/rotate", map[string]string{"identity_token": candidate.Token}, nil); err != nil {
			return err
		}
		_, err = probe.request(ctx, "POST", "/rotate/confirm", struct{}{}, &confirmed)
	}
	if err != nil {
		return err
	}
	if confirmed.Token != candidate.Token || confirmed.AgentID != candidate.AgentID || confirmed.VPSID != candidate.VPSID || confirmed.Version != candidate.Version {
		return errors.New("rotation confirmation mismatch")
	}
	if err = c.save("identity.json", confirmed); err != nil {
		return err
	}
	c.identity = confirmed
	return c.removeState("rotation-pending.json")
}
func (c *Client) submitReceipt(ctx context.Context, name string, result receipt) error {
	c.cachedInstancesValid = false
	status, err := c.request(ctx, "POST", "/results", result, nil)
	if err == nil {
		return c.removeState(name)
	}
	if status == 409 {
		// Retain evidence separately; never relabel a stale result as success.
		if err = c.save("stale-"+name, result); err != nil {
			return err
		}
		return c.removeState(name)
	}
	return err
}
func (c *Client) replayReceipts(ctx context.Context) error {
	entries, err := os.ReadDir(c.StateDir)
	if err != nil {
		return err
	}
	n := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "receipt-") || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		n++
		if n > 100 {
			return errors.New("receipt backlog requires reconciliation")
		}
		data, err := c.readState(e.Name())
		if err != nil {
			return err
		}
		var r receipt
		if json.Unmarshal(data, &r) != nil || r.TaskID == "" || (r.Release == nil && r.Lifecycle == nil && r.LifecycleObservation == nil && r.FRP == nil && !r.Inventory.Valid()) || (r.LifecycleObservation != nil && (!r.LifecycleObservation.Valid() || r.LifecycleObservation.TaskID != r.TaskID || r.LifecycleObservation.Fencing != uint64(r.Fencing))) || (r.FRP != nil && (!r.FRP.Valid() || r.FRP.TaskID != r.TaskID || r.FRP.Fencing != uint64(r.Fencing))) {
			return errors.New("invalid stored receipt")
		}
		if err = c.submitReceipt(ctx, e.Name(), r); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) ConfigureExecutor(socket string) error {
	if socket == "" {
		return nil
	}
	executor, err := agentbridge.New(socket)
	if err != nil {
		return err
	}
	c.Executor = executor
	return nil
}

func (c *Client) ConfigureAutoExecutor(socket string, paths agentconfig.Paths) error {
	if socket != "" {
		if _, err := os.Lstat(socket); err == nil {
			return c.ConfigureExecutor(socket)
		}
	}
	if os.Geteuid() == 0 {
		executor, err := agentbridge.NewInProcess(paths)
		if err != nil {
			return err
		}
		c.Executor = executor
		return nil
	}
	return c.ConfigureExecutor(socket)
}

type inflightRelease struct {
	TaskID     string `json:"task_id"`
	Fencing    int64  `json:"fencing"`
	InstanceID string `json:"instance_id"`
}

func terminalRelease(state string) bool {
	return state == "succeeded" || state == "failed_rolled_back" || state == "failed_manual"
}
func (c *Client) executeRelease(ctx context.Context, cmd agentproto.Lease) error {
	if c.Executor == nil {
		return errors.New("release executor unavailable")
	}
	var req release.Request
	if json.Unmarshal(cmd.Payload, &req) != nil || req.InstanceID == "" || (cmd.Kind == "release" && (req.TaskID != cmd.TaskID || req.Fencing != uint64(cmd.Fencing))) {
		return errors.New("release task payload mismatch")
	}
	inflightName := fmt.Sprintf("inflight-release-%s-%d.json", cmd.TaskID, cmd.Fencing)
	if cmd.Kind == "release" {
		if err := c.save(inflightName, inflightRelease{cmd.TaskID, cmd.Fencing, req.InstanceID}); err != nil {
			return err
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	finished := make(chan struct{})
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-finished:
				return
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if _, err := c.request(runCtx, "POST", "/lease", map[string]any{"task_id": cmd.TaskID, "fencing": cmd.Fencing}, nil); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	var observed release.State
	var err error
	if cmd.Kind == "release_reconcile" {
		observed, err = reconcileRelease(runCtx, c.Executor, req.InstanceID, req.TaskID)
	} else {
		observed, err = c.Executor.Apply(runCtx, req)
	}
	close(finished)
	<-renewed
	var bridgeError *agentbridge.Error
	if errors.As(err, &bridgeError) && bridgeError.Unknown {
		return errors.New("executor result unknown; durable local recovery and status reconciliation required")
	}
	// Preserve actual helper state, including a preflight failure's old state.
	// The panel must not interpret an old state as proof of this publication.
	r := receipt{TaskID: cmd.TaskID, Fencing: cmd.Fencing, Release: &observed}
	if errors.As(err, &bridgeError) {
		r.ExecutionError = bridgeError.Code
	}
	name := fmt.Sprintf("receipt-%s-%d.json", cmd.TaskID, cmd.Fencing)
	if e := c.save(name, r); e != nil {
		return e
	}
	if e := c.removeState(inflightName); e != nil {
		return e
	}
	return c.submitReceipt(ctx, name, r)
}
func (c *Client) reconcileInflight(ctx context.Context) error {
	entries, err := os.ReadDir(c.StateDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "inflight-release-") {
			continue
		}
		if c.Executor == nil {
			continue
		}
		data, err := c.readState(entry.Name())
		if err != nil {
			return err
		}
		var pending inflightRelease
		if json.Unmarshal(data, &pending) != nil {
			return errors.New("invalid inflight release state")
		}
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		state, err := c.Executor.Receipt(probeCtx, pending.InstanceID, pending.TaskID)
		cancel()
		if err != nil {
			continue
		}
		if state.LastTaskID != pending.TaskID || state.Fencing != uint64(pending.Fencing) || !terminalRelease(state.LastResult) {
			// Retain unresolved evidence without starving a fresh read-only
			// reconciliation command or unrelated inventory. Never repeat Apply.
			continue
		}
		r := receipt{TaskID: pending.TaskID, Fencing: pending.Fencing, Release: &state}
		name := fmt.Sprintf("receipt-%s-%d.json", pending.TaskID, pending.Fencing)
		if err = c.save(name, r); err != nil {
			return err
		}
		if err = c.removeState(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) HasIdentity() bool { return c.identity.Token != "" }
func (c *Client) ConfigureBinding(b agentconfig.Binding) error {
	if c.HasIdentity() && b.VPSID != "" && b.VPSID != c.identity.VPSID {
		if c.StaticCredential != "" {
			c.identity = identity{}
			_ = c.removeState("identity.json")
			_ = c.removeState("enrollment-pending.json")
		} else {
			return errors.New("config VPS binding does not match registered identity")
		}
	}
	c.binding = b
	return nil
}
func (c *Client) ValidateBinding(ctx context.Context) error {
	if c.binding.VPSID == "" && c.binding.NodeID == "" {
		return nil
	}
	if c.binding.VPSID != "" && c.binding.VPSID != c.identity.VPSID {
		return errors.New("config VPS binding does not match registered identity")
	}
	b := c.binding
	if b.VPSID == "" {
		b.VPSID = c.identity.VPSID
	}
	status, e := c.request(ctx, "POST", "/binding/check", b, nil)
	if status == 401 && c.StaticCredential != "" {
		c.identity = identity{}
		_ = c.removeState("identity.json")
		_ = c.removeState("enrollment-pending.json")
		if err := c.Enroll(ctx, c.StaticCredential); err != nil {
			return err
		}
		if b.VPSID == "" || c.binding.VPSID == "" {
			b.VPSID = c.identity.VPSID
		}
		_, e = c.request(ctx, "POST", "/binding/check", b, nil)
	}
	return e
}
