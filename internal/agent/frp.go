package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"lineops-agent/internal/agentconfig"
	"lineops-agent/internal/agentproto"
	"lineops-agent/internal/release"
	"time"
)

func (c *Client) executeFRP(ctx context.Context, cmd agentproto.Lease) error {
	var req release.FRPRequest
	if json.Unmarshal(cmd.Payload, &req) != nil || !req.Valid() || req.TaskID != cmd.TaskID || req.Kind != cmd.Kind || req.Fencing != uint64(cmd.Fencing) {
		return errors.New("frp_payload_mismatch")
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
	result := release.ApplyFRP(run, agentconfig.NewPaths(), req)
	close(done)
	<-joined
	r := receipt{TaskID: req.TaskID, Fencing: int64(req.Fencing), FRP: &result}
	name := fmt.Sprintf("receipt-%s-%d.json", req.TaskID, req.Fencing)
	if err := c.save(name, r); err != nil {
		return err
	}
	return c.submitReceipt(ctx, name, r)
}
