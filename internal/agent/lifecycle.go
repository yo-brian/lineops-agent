package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lineop-agent/internal/release"
	"lineop-agent/internal/agentproto"
	"os"
	"strings"
	"time"
)

func (c *Client) executeLifecycle(ctx context.Context, cmd agentproto.Lease) error {
	if c.Executor == nil {
		return errors.New("lifecycle_executor_unavailable")
	}
	var req release.LifecycleRequest
	if json.Unmarshal(cmd.Payload, &req) != nil || !req.Valid() || req.TaskID != cmd.TaskID || req.Kind != cmd.Kind || req.Fencing != uint64(cmd.Fencing) {
		return errors.New("lifecycle_payload_mismatch")
	}
	name := fmt.Sprintf("inflight-lifecycle-%s-%d.json", cmd.TaskID, cmd.Fencing)
	if err := c.save(name, req); err != nil {
		return err
	}
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		ticker := time.NewTicker(10 * time.Second)
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
	result, err := c.Executor.Lifecycle(run, req, false)
	close(done)
	<-joined
	if err != nil {
		return err
	}
	return c.saveLifecycleReceipt(ctx, name, req, result)
}
func (c *Client) saveLifecycleReceipt(ctx context.Context, inflight string, req release.LifecycleRequest, result release.LifecycleResult) error {
	if result.TaskID != req.TaskID || result.InstanceID != req.InstanceID || result.Epoch != req.Epoch || result.Kind != req.Kind || result.Fencing != req.Fencing {
		return errors.New("lifecycle_receipt_mismatch")
	}
	r := receipt{TaskID: req.TaskID, Fencing: int64(req.Fencing), Lifecycle: &result}
	name := fmt.Sprintf("receipt-%s-%d.json", req.TaskID, req.Fencing)
	if err := c.save(name, r); err != nil {
		return err
	}
	if err := c.removeState(inflight); err != nil {
		return err
	}
	return c.submitReceipt(ctx, name, r)
}
func (c *Client) reconcileLifecycle(ctx context.Context) error {
	if c.Executor == nil {
		return nil
	}
	entries, err := os.ReadDir(c.StateDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "inflight-lifecycle-") {
			continue
		}
		data, err := c.readState(entry.Name())
		if err != nil {
			return err
		}
		var req release.LifecycleRequest
		if json.Unmarshal(data, &req) != nil || !req.Valid() {
			return errors.New("invalid_inflight_lifecycle")
		}
		result, err := c.Executor.Lifecycle(ctx, req, true)
		if err != nil || result.State == "unknown" {
			continue
		}
		if err = c.saveLifecycleReceipt(ctx, entry.Name(), req, result); err != nil {
			return err
		}
	}
	return nil
}
