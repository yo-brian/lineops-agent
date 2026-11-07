package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lineops-agent/internal/agentproto"
	"lineops-agent/internal/release"
	"time"
)

type lifecycleReconcileExecutor interface {
	Capabilities(context.Context) ([]string, []string, error)
	LifecycleReconcile(context.Context, release.LifecycleReconcileRequest) (release.LifecycleObservation, error)
}

func (c *Client) executeLifecycleReconcile(ctx context.Context, cmd agentproto.Lease) error {
	if c.Executor == nil {
		return errors.New("lifecycle_executor_unavailable")
	}
	return c.executeLifecycleObservation(ctx, cmd, c.Executor, 10*time.Second)
}

func (c *Client) executeLifecycleObservation(ctx context.Context, cmd agentproto.Lease, executor lifecycleReconcileExecutor, renewal time.Duration) error {
	var req release.LifecycleReconcileRequest
	if cmd.Kind != "singbox_reconcile" || json.Unmarshal(cmd.Payload, &req) != nil || !req.Valid() || req.TaskID != cmd.TaskID || req.Fencing != uint64(cmd.Fencing) {
		return errors.New("lifecycle_reconcile_payload_mismatch")
	}
	probe, stopProbe := context.WithTimeout(ctx, 3*time.Second)
	_, capabilities, err := executor.Capabilities(probe)
	stopProbe()
	supported := false
	for _, capability := range capabilities {
		supported = supported || capability == "singbox_reconcile_v1"
	}
	if err != nil || !supported {
		return errors.New("lifecycle_reconcile_unsupported")
	}
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	done, joined := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(renewal)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-run.Done():
				return
			case <-ticker.C:
				if _, err := c.request(run, "POST", "/lease", map[string]any{"task_id": cmd.TaskID, "fencing": cmd.Fencing}, nil); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	result, err := executor.LifecycleReconcile(run, req)
	close(done)
	cancel() // Drain even a renewal request already in flight before returning.
	<-joined
	if err != nil {
		return err
	}
	if !result.Matches(req) {
		return errors.New("lifecycle_observation_mismatch")
	}
	r := receipt{TaskID: cmd.TaskID, Fencing: cmd.Fencing, LifecycleObservation: &result}
	name := fmt.Sprintf("receipt-%s-%d.json", cmd.TaskID, cmd.Fencing)
	if err = c.save(name, r); err != nil {
		return err
	}
	return c.submitReceipt(ctx, name, r)
}
