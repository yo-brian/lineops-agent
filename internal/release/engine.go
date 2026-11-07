package release

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lineops-agent/internal/agentconfig"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

type RuntimeConfig struct {
	TrafficAPI     bool   `json:"traffic_api,omitempty"`
	InstanceID     string `json:"instance_id"`
	Epoch          string `json:"epoch"`
	Binary         string `json:"binary"`
	BinarySHA256   string `json:"binary_sha256"`
	BinaryVersion  string `json:"binary_version"`
	RecoveryBinary string `json:"recovery_binary"`
	ServiceUser    string `json:"service_user"`
}
type State struct {
	InstanceID          string    `json:"instance_id"`
	Epoch               string    `json:"epoch"`
	Generation          uint64    `json:"generation"`
	Fencing             uint64    `json:"fencing"`
	CurrentVersion      string    `json:"current_version"`
	VerifiedVersion     string    `json:"verified_version"`
	LastTaskID          string    `json:"last_task_id"`
	RequestDigest       string    `json:"request_digest,omitempty"`
	PolicyFailureDigest string    `json:"policy_failure_digest,omitempty"`
	LastResult          string    `json:"last_result"`
	ErrorCode           string    `json:"error_code,omitempty"`
	ObservedAt          time.Time `json:"observed_at"`
}
type Journal struct {
	TaskID           string    `json:"task_id"`
	RequestDigest    string    `json:"request_digest"`
	Epoch            string    `json:"epoch"`
	Generation       uint64    `json:"generation"`
	Fencing          uint64    `json:"fencing"`
	OldVersion       string    `json:"old_version"`
	CandidateVersion string    `json:"candidate_version"`
	State            string    `json:"state"`
	StartedAt        time.Time `json:"started_at"`
	Deadline         time.Time `json:"deadline"`
	BootID           string    `json:"boot_id"`
	RecoveryAttempts int       `json:"recovery_attempts"`
	ErrorCode        string    `json:"error_code,omitempty"`
}

// Runtime methods must use the registered binary/service identity and managed
// paths. The production implementation is SystemdRuntime; test fakes do not
// constitute protocol or recovery acceptance.
type Runtime interface {
	Check(context.Context, RuntimeConfig, string) error
	Trial(context.Context, RuntimeConfig, string) error
	Guard(context.Context, RuntimeConfig, string, Journal) error
	Restart(context.Context, RuntimeConfig, string) error
	Stop(context.Context, RuntimeConfig) error
	Healthy(context.Context, RuntimeConfig, string, Model) error
}
type Engine struct {
	Paths   agentconfig.Paths
	Root    string
	Runtime Runtime
}

func (e Engine) open(id string) (string, RuntimeConfig, State, error) {
	var r RuntimeConfig
	var s State
	if !identifier.MatchString(id) {
		return "", r, s, errors.New("invalid instance ID")
	}
	if err := safeDir(e.Root, false); err != nil {
		return "", r, s, err
	}
	dir := filepath.Join(e.Root, id)
	if err := safeDir(dir, false); err != nil {
		return "", r, s, err
	}
	if err := readJSON(filepath.Join(dir, "runtime.json"), &r); err != nil {
		return "", r, s, err
	}
	if r.InstanceID != id {
		return "", r, s, errors.New("instance registration mismatch")
	}
	if err := readJSON(filepath.Join(dir, "state.json"), &s); err != nil {
		return "", r, s, err
	}
	if s.InstanceID != id || s.Epoch != r.Epoch {
		return "", r, s, errors.New("local state instance or epoch mismatch")
	}
	return dir, r, s, nil
}
func (e Engine) locks(ctx context.Context, id string) (func(), error) {
	if e.Runtime == nil {
		return nil, errors.New("real runtime not configured")
	}
	if !identifier.MatchString(id) {
		return nil, errors.New("invalid instance ID")
	}
	if err := safeDir(e.Root, false); err != nil {
		return nil, err
	}
	if err := safeDir(filepath.Join(e.Root, id), false); err != nil {
		return nil, err
	}
	a, err := acquire(ctx, filepath.Join(e.Root, "host-ports.lock"))
	if err != nil {
		return nil, err
	}
	b, err := acquire(ctx, filepath.Join(e.Root, id, "instance.lock"))
	if err != nil {
		a()
		return nil, err
	}
	return func() { b(); a() }, nil
}
func (e Engine) Status(id string) (State, error) { _, _, s, err := e.open(id); return s, err }

// Receipt is an immutable per-business-task outcome; a later offline policy
// event must not erase the evidence needed to reconcile a lost Agent response.
func (e Engine) Receipt(id, task string) (State, error) {
	dir, r, s, err := e.open(id)
	if err != nil {
		return s, err
	}
	if !identifier.MatchString(task) {
		return State{}, errors.New("invalid task ID")
	}
	var receipt State
	err = readJSON(filepath.Join(dir, "receipts", task+".json"), &receipt)
	if err == nil {
		if receipt.InstanceID != id || receipt.LastTaskID != task || receipt.Epoch != r.Epoch {
			return State{}, errors.New("receipt identity mismatch")
		}
		return receipt, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return State{}, err
	}
	if s.LastTaskID == task && (s.LastResult == "succeeded" || s.LastResult == "failed_manual" || s.LastResult == "failed_rolled_back") {
		return s, nil
	}
	j, x := activeJournal(dir)
	if x == nil && j.TaskID == task && j.State == "committed" && j.Epoch == r.Epoch {
		if _, _, x = verifyVersion(dir, j.CandidateVersion); x != nil {
			return State{}, x
		}
		return State{InstanceID: id, Epoch: r.Epoch, Generation: j.Generation, Fencing: j.Fencing, CurrentVersion: j.CandidateVersion, VerifiedVersion: j.CandidateVersion, LastTaskID: task, RequestDigest: j.RequestDigest, LastResult: "succeeded", ObservedAt: j.StartedAt}, nil
	}
	return State{}, errors.New("task receipt unavailable; publication remains unknown")
}
func writeReceipt(dir string, s State) error {
	if !identifier.MatchString(s.LastTaskID) {
		return errors.New("invalid receipt task")
	}
	receiptDir := filepath.Join(dir, "receipts")
	if err := safeDir(receiptDir, true); err != nil {
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	path := filepath.Join(receiptDir, s.LastTaskID+".json")
	var old State
	if err := readJSON(path, &old); err == nil {
		if old.RequestDigest == s.RequestDigest && old.Generation == s.Generation && old.Fencing == s.Fencing && old.LastResult == s.LastResult {
			return nil
		}
		return errors.New("immutable receipt conflict")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeJSON(path, s)
}
func (e Engine) VerifyStatus(ctx context.Context, id string) (State, error) {
	unlock, err := e.locks(ctx, id)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	return e.verifyStatusLocked(ctx, id)
}

// Caller holds the host and instance locks, including during read-only lifecycle observation.
func (e Engine) verifyStatusLocked(ctx context.Context, id string) (State, error) {
	dir, r, s, err := e.open(id)
	if err != nil {
		return s, err
	}
	fail := func(code string) (State, error) {
		s.LastResult = "failed_manual"
		s.ErrorCode = code
		s.ObservedAt = time.Now().UTC()
		return s, errors.New(code)
	}
	if s.CurrentVersion == "" || s.CurrentVersion != s.VerifiedVersion {
		return fail("current_version_not_verified")
	}
	m, desired, err := verifyVersion(dir, s.CurrentVersion)
	if err != nil {
		return fail("configuration_or_dependency_drift")
	}
	target, err := os.Readlink(filepath.Join(dir, "current"))
	if err != nil || target != "versions/"+s.CurrentVersion {
		return fail("current_pointer_drift")
	}
	p, err := loadPolicies(dir, r.Epoch)
	if err != nil || p.Epoch != r.Epoch {
		return fail("authorization_policy_unavailable")
	}
	if err = e.Runtime.Healthy(ctx, r, filepath.Join(dir, "versions", s.CurrentVersion), m); err != nil {
		return fail("fresh_protocol_health_failed")
	}
	latest, err := p.Effective(desired, time.Now())
	if err != nil || !reflect.DeepEqual(latest, m) {
		return fail("authorization_not_verified")
	}
	s.ObservedAt = time.Now().UTC()
	s.ErrorCode = ""
	return s, nil
}

// StartGate is a read-only ExecStartPre guard. It must not take the publisher
// lock: systemctl restart is called while that lock is held.
func (e Engine) StartGate(id string) error {
	dir, r, _, err := e.open(id)
	if err != nil {
		return err
	}
	target, err := os.Readlink(filepath.Join(dir, "current"))
	if err != nil || !strings.HasPrefix(target, "versions/") {
		return errors.New("managed current pointer unavailable")
	}
	version := strings.TrimPrefix(target, "versions/")
	effective, desired, err := verifyVersion(dir, version)
	if err != nil {
		return err
	}
	p, err := loadPolicies(dir, r.Epoch)
	if err != nil || p.Epoch != r.Epoch {
		return errors.New("startup authorization epoch mismatch")
	}
	latest, err := p.Effective(desired, time.Now())
	if err != nil {
		return err
	}
	a, _ := json.Marshal(effective)
	b, _ := json.Marshal(latest)
	if digest(a) != digest(b) {
		return errors.New("startup blocked until latest authorization is rendered")
	}
	j, x := activeJournal(dir)
	if x != nil && !errors.Is(x, os.ErrNotExist) {
		return errors.New("startup blocked by unreadable release journal")
	}
	if x == nil && pending(j) && j.BootID != bootID() && version == j.CandidateVersion {
		return errors.New("startup blocked until interrupted publication is recovered")
	}
	return nil
}
func loadPolicies(dir, epoch string) (PolicySet, error) {
	p := PolicySet{Epoch: epoch, Groups: map[string]GroupPolicy{}}
	err := readJSON(filepath.Join(dir, "policies.json"), &p)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	return p, err
}
func activeJournal(dir string) (Journal, error) {
	var j Journal
	err := readJSON(filepath.Join(dir, "journal.json"), &j)
	return j, err
}
func pending(j Journal) bool {
	return j.State == "prepared" || j.State == "switched" || j.State == "recovering"
}

type preflightRejection struct{ cause error }

func (p *preflightRejection) Error() string { return p.cause.Error() }
func (p *preflightRejection) Unwrap() error { return p.cause }
func (e Engine) Apply(ctx context.Context, req Request) (State, error) {
	unlock, err := e.locks(ctx, req.InstanceID)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	var result State
	applyErr := timedStage(req.TaskID, "apply_total", func() error {
		var err error
		result, err = e.applyLocked(ctx, req, false)
		return err
	})
	var rejected *preflightRejection
	if errors.As(applyErr, &rejected) {
		dir, r, old, x := e.open(req.InstanceID)
		if x != nil {
			return result, x
		}
		if identifier.MatchString(req.TaskID) && req.Epoch == r.Epoch && req.Generation > old.Generation && req.Fencing > old.Fencing {
			b, _ := json.Marshal(req)
			result = old
			result.LastTaskID = req.TaskID
			result.RequestDigest = digest(b)
			result.Generation = req.Generation
			result.Fencing = req.Fencing
			result.LastResult = "failed_manual"
			result.ErrorCode = "preflight_rejected"
			result.ObservedAt = time.Now().UTC()
			if x = writeReceipt(dir, result); x != nil {
				return result, x
			}
		}
	}
	return result, applyErr
}
func (e Engine) applyLocked(ctx context.Context, req Request, policyOnly bool) (State, error) {
	dir, r, s, err := e.open(req.InstanceID)
	if err != nil {
		return s, err
	}
	if !identifier.MatchString(req.TaskID) || req.Epoch != r.Epoch || req.Policies.Epoch != r.Epoch {
		return s, errors.New("invalid task or deployment epoch")
	}
	requestBytes, _ := json.Marshal(req)
	requestDigest := digest(requestBytes)
	var historical State
	if x := readJSON(filepath.Join(dir, "receipts", req.TaskID+".json"), &historical); x == nil {
		if historical.RequestDigest != requestDigest || historical.Generation != req.Generation || historical.Fencing != req.Fencing {
			return s, errors.New("conflicting task replay")
		}
		if historical.LastResult != "succeeded" {
			return historical, errors.New("previous task is not a successful publication; reconcile receipt")
		}
		return historical, nil
	} else if !errors.Is(x, os.ErrNotExist) {
		return s, x
	}
	// Archive the previous terminal result before another task can replace its
	// journal, including commit-after-fsync/before-state-write crash recovery.
	if s.LastTaskID != "" {
		if previous, x := e.Receipt(req.InstanceID, s.LastTaskID); x == nil {
			if x = writeReceipt(dir, previous); x != nil {
				return s, x
			}
		}
	}
	if s.LastTaskID == req.TaskID {
		if s.Fencing == req.Fencing && s.Generation == req.Generation && s.RequestDigest == requestDigest {
			if s.LastResult != "succeeded" {
				return s, errors.New("previous task is not a successful publication; reconcile receipt")
			}
			return s, nil
		}
		return s, errors.New("conflicting task replay")
	}
	if req.Generation <= s.Generation || req.Fencing <= s.Fencing {
		return s, errors.New("stale generation or fencing")
	}
	reject := func(cause error) (State, error) { return s, &preflightRejection{cause: cause} }
	if req.RecoverySeconds < 15 || req.RecoverySeconds > 300 {
		return reject(errors.New("recovery window must be 15..300 seconds"))
	}
	if len(req.RenderedConfig) > 0 {
		if err = ValidatePreRenderedModel(req.Model, req.Certificates, time.Now()); err != nil {
			return reject(err)
		}
	} else if err = validateShape(req.Model); err != nil {
		return reject(err)
	}
	if j, x := activeJournal(dir); x == nil {
		if pending(j) {
			return reject(errors.New("unconfirmed publication requires recovery"))
		}
	} else if !errors.Is(x, os.ErrNotExist) {
		return reject(errors.New("release journal unreadable; manual reconciliation required"))
	}
	old := Model{Schema: 1, Template: Template, Nodes: []Node{}}
	if s.CurrentVersion != "" {
		actual, d, x := verifyVersion(dir, s.CurrentVersion)
		if x != nil {
			return reject(x)
		}
		old = d
		if target, x := os.Readlink(filepath.Join(dir, "current")); x != nil || target != "versions/"+s.CurrentVersion {
			return reject(errors.New("current pointer drift"))
		}
		if !policyOnly {
			if err = timedStage(req.TaskID, "baseline_health", func() error {
				return e.Runtime.Healthy(ctx, r, filepath.Join(dir, "versions", s.CurrentVersion), actual)
			}); err != nil {
				return reject(errors.New("baseline health failed"))
			}
		}
		if err = certImpact(dir, s.CurrentVersion, old, req.Model, req.Certificates, req.TargetGroups); err != nil {
			return reject(err)
		}
	}
	if _, err = SemanticDiff(old, req.Model, req.TargetGroups); err != nil {
		return reject(err)
	}
	p, err := loadPolicies(dir, r.Epoch)
	if err != nil {
		return reject(err)
	}
	p, err = MergePolicies(p, req.Policies)
	if err != nil {
		return reject(err)
	}
	effective, err := p.Effective(req.Model, time.Now())
	if err != nil {
		return reject(err)
	}
	if len(req.RenderedConfig) > 0 {
		if err = ValidatePreRenderedModel(effective, req.Certificates, time.Now()); err != nil {
			return reject(err)
		}
	} else if err = ValidateModel(effective, req.Certificates, time.Now()); err != nil {
		return reject(err)
	}
	if err = e.checkPorts(req.InstanceID, req.Model); err != nil {
		return reject(err)
	}
	// All branches above provably performed no publication/policy side effect.
	// From this point onward errors must not be recorded as "not executed".
	if err = writeJSON(filepath.Join(dir, "policies.json"), p); err != nil {
		return s, err
	}
	version := fmt.Sprintf("v-%d-%d", req.Generation, req.Fencing)
	if _, err = freezeVersion(dir, version, req.Model, effective, req.Certificates, req.RenderedConfig); err != nil {
		return s, err
	}
	vdir := filepath.Join(dir, "versions", version)
	preparationFailed := func(code string) (State, error) {
		s.Generation = req.Generation
		s.Fencing = req.Fencing
		s.LastTaskID = req.TaskID
		s.RequestDigest = requestDigest
		s.LastResult = "failed_manual"
		s.ErrorCode = code
		s.ObservedAt = time.Now().UTC()
		if x := writeJSON(filepath.Join(dir, "state.json"), s); x != nil {
			return s, x
		}
		if x := writeReceipt(dir, s); x != nil {
			return s, x
		}
		return s, errors.New(code)
	}
	if err = timedStage(req.TaskID, "config_check", func() error { return e.Runtime.Check(ctx, r, vdir) }); err != nil {
		return preparationFailed("sing_box_check_failed")
	}
	if err = timedStage(req.TaskID, "isolated_trial", func() error { return e.Runtime.Trial(ctx, r, vdir) }); err != nil {
		return preparationFailed("isolated_trial_failed")
	}
	if _, _, err = verifyVersion(dir, version); err != nil {
		return s, err
	}
	now := time.Now().UTC()
	j := Journal{TaskID: req.TaskID, RequestDigest: requestDigest, Epoch: req.Epoch, Generation: req.Generation, Fencing: req.Fencing, OldVersion: s.CurrentVersion, CandidateVersion: version, State: "prepared", StartedAt: now, Deadline: now.Add(time.Duration(req.RecoverySeconds) * time.Second), BootID: bootID()}
	if err = writeJSON(filepath.Join(dir, "journal.json"), j); err != nil {
		return s, err
	}
	if err = timedStage(req.TaskID, "recovery_guard", func() error { return e.Runtime.Guard(ctx, r, e.Root, j) }); err != nil {
		j.State = "failed_before_switch"
		j.ErrorCode = "independent_guard_failed"
		_ = writeJSON(filepath.Join(dir, "journal.json"), j)
		return s, errors.New("independent recovery guard unavailable")
	}
	if err = switchCurrent(dir, version); err != nil {
		return s, err
	}
	j.State = "switched"
	if err = writeJSON(filepath.Join(dir, "journal.json"), j); err != nil {
		return s, err
	}
	s.Generation = req.Generation
	s.Fencing = req.Fencing
	s.LastTaskID = req.TaskID
	s.RequestDigest = requestDigest
	s.CurrentVersion = version
	s.LastResult = "verifying"
	s.ObservedAt = now
	if err = writeJSON(filepath.Join(dir, "state.json"), s); err != nil {
		return s, err
	}
	verifyCtx, cancel := context.WithDeadline(ctx, j.Deadline)
	defer cancel()
	err = timedStage(req.TaskID, "restart", func() error { return e.Runtime.Restart(verifyCtx, r, dir) })
	if err == nil {
		err = timedStage(req.TaskID, "protocol_health", func() error { return e.Runtime.Healthy(verifyCtx, r, vdir, effective) })
	}
	if err != nil || time.Now().After(j.Deadline) {
		j.ErrorCode = "activation_or_health_failed"
		_ = writeJSON(filepath.Join(dir, "journal.json"), j)
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		s, recErr := e.recoverLocked(recoveryCtx, r, dir, s, j)
		if recErr != nil {
			return s, recErr
		}
		return s, errors.New("publication failed; previous service safely restored")
	}
	// Recheck policy against the commit instant, including expiration during trial.
	latest, x := loadPolicies(dir, r.Epoch)
	if x != nil {
		return s, x
	}
	current, x := latest.Effective(req.Model, time.Now())
	if x != nil || !reflect.DeepEqual(current, effective) {
		return s, errors.New("authorization changed during publication; recovery guard remains armed")
	}
	j.State = "committed"
	if err = writeJSON(filepath.Join(dir, "journal.json"), j); err != nil {
		return s, err
	}
	s.VerifiedVersion = version
	s.LastResult = "succeeded"
	s.ErrorCode = ""
	s.PolicyFailureDigest = ""
	s.ObservedAt = time.Now().UTC()
	if err = writeReceipt(dir, s); err != nil {
		return s, err
	}
	if err = writeJSON(filepath.Join(dir, "state.json"), s); err != nil {
		return s, err
	}
	return s, nil
}
func certImpact(dir, version string, old, next Model, certs []Certificate, targets []string) error {
	allowed := map[string]bool{}
	for _, id := range targets {
		allowed[id] = true
	}
	newAssets := map[string]Certificate{}
	for _, c := range certs {
		newAssets[c.ID] = c
	}
	for _, n := range next.Nodes {
		if !n.UsesCertificate() {
			continue
		}
		if allowed[n.GroupID] {
			continue
		}
		for _, prev := range old.Nodes {
			if prev.ID == n.ID {
				c, ok := newAssets[n.CertificateID]
				if !ok {
					return errors.New("missing unchanged group TLS")
				}
				b, e := readRegular(filepath.Join(dir, "versions", version, "tls-"+n.CertificateID+".pem"))
				k, f := readRegular(filepath.Join(dir, "versions", version, "key-"+n.CertificateID+".pem"))
				t, g := readRegular(filepath.Join(dir, "versions", version, "trust-"+n.CertificateID+".pem"))
				if e != nil || f != nil || g != nil || digest(b) != digest(c.CertificatePEM) || digest(k) != digest(c.PrivateKeyPEM) || digest(t) != digest(c.TrustPEM) {
					return errors.New("unapproved shared TLS dependency change")
				}
			}
		}
	}
	return nil
}
func (e Engine) checkPorts(id string, m Model) error {
	var current RuntimeConfig
	if err := readJSON(filepath.Join(e.Root, id, "runtime.json"), &current); err != nil {
		return err
	}
	candidates := append([]Node{}, m.Nodes...)
	if current.TrafficAPI {
		candidates = append(candidates, trafficListener(id, m))
	}
	entries, err := os.ReadDir(e.Root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == id || !identifier.MatchString(entry.Name()) {
			continue
		}
		dir, runtime, s, x := e.open(entry.Name())
		if x != nil {
			return errors.New("unreadable sibling instance; port planning blocked")
		}
		if s.CurrentVersion == "" {
			continue
		}
		_, other, x := verifyVersion(dir, s.CurrentVersion)
		if x != nil {
			return x
		}
		reservations := append([]Node{}, other.Nodes...)
		if runtime.TrafficAPI {
			reservations = append(reservations, trafficListener(entry.Name(), other))
		}
		for _, a := range candidates {
			for _, b := range reservations {
				if PortConflict(a, b) {
					return errors.New("VPS port reservation conflicts with another instance")
				}
			}
		}
	}
	return nil
}
func (e Engine) Recover(ctx context.Context, id, task string, fencing uint64, boot bool) (State, error) {
	unlock, err := e.locks(ctx, id)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	dir, r, s, err := e.open(id)
	if err != nil {
		return s, err
	}
	j, err := activeJournal(dir)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if !pending(j) || j.TaskID != task || j.Fencing != fencing || j.Epoch != r.Epoch || s.Generation > j.Generation || s.Fencing > j.Fencing {
		return s, nil
	}
	if !boot && time.Now().Before(j.Deadline) && bootID() == j.BootID {
		return s, nil
	}
	return e.recoverLocked(ctx, r, dir, s, j)
}
func (e Engine) recoverLocked(ctx context.Context, r RuntimeConfig, dir string, s State, j Journal) (State, error) {
	if !pending(j) || j.Epoch != r.Epoch || s.Generation > j.Generation || s.Fencing > j.Fencing {
		return s, nil
	}
	if j.RecoveryAttempts >= 1 {
		j.State = "failed_manual"
		j.ErrorCode = "recovery_attempt_interrupted_or_exhausted"
		_ = writeJSON(filepath.Join(dir, "journal.json"), j)
		s.LastResult = "failed_manual"
		s.LastTaskID = j.TaskID
		s.RequestDigest = j.RequestDigest
		s.Generation = j.Generation
		s.Fencing = j.Fencing
		s.ErrorCode = j.ErrorCode
		s.ObservedAt = time.Now().UTC()
		_ = writeJSON(filepath.Join(dir, "state.json"), s)
		_ = writeReceipt(dir, s)
		return s, errors.New("recovery exhausted; manual repair required")
	}
	j.State = "recovering"
	j.RecoveryAttempts++
	if err := writeJSON(filepath.Join(dir, "journal.json"), j); err != nil {
		return s, err
	}
	fail := func(code string, err error) (State, error) {
		j.State = "failed_manual"
		j.ErrorCode = code
		_ = writeJSON(filepath.Join(dir, "journal.json"), j)
		s.LastTaskID = j.TaskID
		s.RequestDigest = j.RequestDigest
		s.Generation = j.Generation
		s.Fencing = j.Fencing
		s.LastResult = "failed_manual"
		s.ErrorCode = code
		s.ObservedAt = time.Now().UTC()
		_ = writeJSON(filepath.Join(dir, "state.json"), s)
		_ = writeReceipt(dir, s)
		return s, err
	}
	if j.OldVersion == "" {
		if err := e.Runtime.Stop(ctx, r); err != nil {
			return fail("initial_release_stop_failed", err)
		}
		j.State = "failed_rolled_back"
		s.CurrentVersion = ""
		s.VerifiedVersion = ""
		pointer := filepath.Join(dir, "current")
		if info, x := os.Lstat(pointer); x == nil && info.Mode()&os.ModeSymlink != 0 {
			if x = os.Remove(pointer); x != nil {
				return fail("initial_pointer_cleanup_failed", x)
			}
			if x = syncDir(dir); x != nil {
				return fail("initial_pointer_fsync_failed", x)
			}
		}
	} else {
		_, desired, err := verifyVersion(dir, j.OldVersion)
		if err != nil {
			return fail("recovery_dependency_drift", err)
		}
		p, err := loadPolicies(dir, r.Epoch)
		if err != nil {
			return fail("recovery_policy_unreadable", err)
		}
		effective, err := p.Effective(desired, time.Now())
		if err != nil {
			return fail("recovery_authorization_conflict", err)
		}
		certs, err := CertificatesFromDir(filepath.Join(dir, "versions", j.OldVersion), desired)
		if err != nil {
			return fail("recovery_missing_dependencies", err)
		}
		oldRendered, _ := readRegular(filepath.Join(dir, "versions", j.OldVersion, "rendered.json"))
		if len(oldRendered) > 0 {
			if err = ValidatePreRenderedModel(effective, certs, time.Now()); err != nil {
				return fail("recovery_certificate_invalid", err)
			}
		} else if err = ValidateModel(effective, certs, time.Now()); err != nil {
			return fail("recovery_certificate_invalid", err)
		}
		version := fmt.Sprintf("r-%d-%d", j.Generation, j.Fencing)
		if _, err = freezeVersion(dir, version, desired, effective, certs, oldRendered); err != nil {
			return fail("recovery_freeze_failed", err)
		}
		vdir := filepath.Join(dir, "versions", version)
		if err = e.Runtime.Check(ctx, r, vdir); err != nil {
			return fail("recovery_check_failed", err)
		}
		if err = e.Runtime.Trial(ctx, r, vdir); err != nil {
			return fail("recovery_trial_failed", err)
		}
		if err = switchCurrent(dir, version); err != nil {
			return fail("recovery_switch_failed", err)
		}
		s.CurrentVersion = version
		if err = e.Runtime.Restart(ctx, r, dir); err != nil {
			return fail("recovery_restart_failed", err)
		}
		if err = e.Runtime.Healthy(ctx, r, vdir, effective); err != nil {
			return fail("recovery_health_failed", err)
		}
		s.VerifiedVersion = version
		j.State = "failed_rolled_back"
	}
	s.LastTaskID = j.TaskID
	s.RequestDigest = j.RequestDigest
	s.Generation = j.Generation
	s.Fencing = j.Fencing
	s.LastResult = "failed_rolled_back"
	s.ErrorCode = j.ErrorCode
	s.ObservedAt = time.Now().UTC()
	if err := writeJSON(filepath.Join(dir, "journal.json"), j); err != nil {
		return s, err
	}
	if err := writeReceipt(dir, s); err != nil {
		return s, err
	}
	if err := writeJSON(filepath.Join(dir, "state.json"), s); err != nil {
		return s, err
	}
	return s, nil
}
func (e Engine) UpdatePolicies(ctx context.Context, id string, next PolicySet) (State, error) {
	unlock, err := e.locks(ctx, id)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	dir, r, s, err := e.open(id)
	if err != nil {
		return s, err
	}
	old, err := loadPolicies(dir, r.Epoch)
	if err != nil {
		return s, err
	}
	merged, err := MergePolicies(old, next)
	if err != nil {
		return s, err
	}
	if err = writeJSON(filepath.Join(dir, "policies.json"), merged); err != nil {
		return s, err
	}
	return e.reconcilePolicyLocked(ctx, id)
}
func (e Engine) ReconcilePolicy(ctx context.Context, id string) (State, error) {
	unlock, err := e.locks(ctx, id)
	if err != nil {
		return State{}, err
	}
	defer unlock()
	dir, r, s, x := e.open(id)
	if x != nil {
		return s, x
	}
	j, x := activeJournal(dir)
	if x != nil && !errors.Is(x, os.ErrNotExist) {
		return s, errors.New("release journal unreadable; manual reconciliation required")
	}
	if x == nil && pending(j) && (j.BootID != bootID() || time.Now().After(j.Deadline) || time.Now().Before(j.StartedAt.Add(-time.Minute))) {
		if _, x = e.recoverLocked(ctx, r, dir, s, j); x != nil {
			return s, x
		}
	}
	return e.reconcilePolicyLocked(ctx, id)
}
func (e Engine) reconcilePolicyLocked(ctx context.Context, id string) (State, error) {
	dir, r, s, err := e.open(id)
	if err != nil || s.CurrentVersion == "" {
		return s, err
	}
	j, x := activeJournal(dir)
	if x != nil && !errors.Is(x, os.ErrNotExist) {
		return s, errors.New("release journal unreadable; manual reconciliation required")
	}
	if x == nil && pending(j) {
		return s, errors.New("policy saved; unconfirmed release must recover before reconciliation")
	}
	effective, desired, err := verifyVersion(dir, s.CurrentVersion)
	if err != nil {
		return s, err
	}
	p, err := loadPolicies(dir, r.Epoch)
	if err != nil {
		return s, err
	}
	next, err := p.Effective(desired, time.Now())
	if err != nil {
		return s, err
	}
	a, _ := json.Marshal(effective)
	b, _ := json.Marshal(next)
	if digest(a) == digest(b) {
		return s, nil
	}
	policyBytes, _ := json.Marshal(p)
	policyFailureDigest := digest(append(b, policyBytes...))
	if s.PolicyFailureDigest == policyFailureDigest {
		return s, errors.New("failed authorization publication is frozen; new policy or operator repair required")
	}
	certs, err := CertificatesFromDir(filepath.Join(dir, "versions", s.CurrentVersion), desired)
	if err != nil {
		return s, err
	}
	groups := []string{}
	for id := range p.Groups {
		groups = append(groups, id)
	}
	updated, applyErr := e.applyLocked(ctx, Request{TaskID: fmt.Sprintf("policy-%d-%d", s.Generation+1, s.Fencing+1), Epoch: r.Epoch, InstanceID: id, Generation: s.Generation + 1, Fencing: s.Fencing + 1, TargetGroups: groups, Model: desired, Certificates: certs, Policies: p, RecoverySeconds: 45}, true)
	if applyErr != nil {
		updated.PolicyFailureDigest = policyFailureDigest
		updated.ErrorCode = "authorization_not_verified"
		updated.ObservedAt = time.Now().UTC()
		if updated.LastResult == "succeeded" {
			updated.LastResult = "failed_manual"
		}
		_ = writeJSON(filepath.Join(dir, "state.json"), updated)
	}
	return updated, applyErr
}
func (e Engine) Scan(ctx context.Context) map[string]string {
	results := map[string]string{}
	entries, err := os.ReadDir(e.Root)
	if err != nil {
		results["_root"] = "unavailable"
		return results
	}
	for _, entry := range entries {
		if !entry.IsDir() || !identifier.MatchString(entry.Name()) {
			continue
		}
		id := entry.Name()
		func() {
			unlock, x := e.locks(ctx, id)
			if x != nil {
				results[id] = "lock_unavailable"
				return
			}
			defer unlock()
			dir, r, s, x := e.open(id)
			if x != nil {
				results[id] = "invalid_registration"
				return
			}
			j, x := activeJournal(dir)
			if x != nil && !errors.Is(x, os.ErrNotExist) {
				results[id] = "journal_unreadable"
				return
			}
			if x == nil && pending(j) {
				if time.Now().Before(j.StartedAt.Add(-time.Minute)) {
					j.ErrorCode = "clock_moved_backwards"
				}
				if time.Now().After(j.Deadline) || bootID() != j.BootID || j.ErrorCode == "clock_moved_backwards" {
					_, x = e.recoverLocked(ctx, r, dir, s, j)
					if x != nil {
						results[id] = "failed_manual"
						return
					}
				} else {
					results[id] = "pending"
					return
				}
			}
			state, x := e.reconcilePolicyLocked(ctx, id)
			if x != nil {
				results[id] = "policy_reconciliation_failed"
			} else {
				results[id] = state.LastResult
			}
		}()
	}
	return results
}

func (e Engine) ManagedPaths() agentconfig.Paths {
	if e.Paths.AgentBinDir != "" {
		return e.Paths
	}
	return agentconfig.ForRoot(e.Root)
}
