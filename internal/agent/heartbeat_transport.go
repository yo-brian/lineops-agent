package agent

import (
	"context"
	"slices"

	"lineop-agent/internal/agentproto"
	"lineop-agent/internal/traffic"
)

func (c *Client) sendHeartbeat(ctx context.Context, inventory agentproto.Inventory) error {
	return c.sendHeartbeatPage(ctx, inventory, false)
}

func (c *Client) sendHeartbeatPage(ctx context.Context, inventory agentproto.Inventory, partial bool, trafficObserved ...string) error {
	payload := agentproto.PrepareHeartbeat(inventory, c.acknowledgedTraffic, c.heartbeatDelta)
	payload.InstancePartial = partial
	if partial {
		payload.InstanceTrafficObserved = trafficObserved
	}
	optimized := payload.Delta != nil || c.heartbeatGzip
	var ack agentproto.HeartbeatAck
	code, err := c.request(ctx, "POST", "/heartbeat", payload, &ack)
	if err != nil && optimized && (code == 400 || code == 409 || code == 415) {
		// Covers lost acknowledgements, server restore and mixed-version rollout.
		c.heartbeatGzip = false
		c.heartbeatDelta = false
		c.acknowledgedTraffic = nil
		ack = agentproto.HeartbeatAck{}
		full := agentproto.Heartbeat{Inventory: inventory, InstancePartial: partial, InstanceTrafficObserved: payload.InstanceTrafficObserved}
		_, err = c.request(ctx, "POST", "/heartbeat", full, &ack)
	}
	if err != nil {
		return err
	}
	c.heartbeatGzip = slices.Contains(ack.Capabilities, agentproto.HeartbeatGzip)
	c.heartbeatDelta = slices.Contains(ack.Capabilities, agentproto.HeartbeatDelta)
	c.acknowledgedTraffic = nil
	if ack.TrafficHash == agentproto.TrafficHash(inventory.NodeTraffic) {
		c.acknowledgedTraffic = append([]traffic.Sample(nil), inventory.NodeTraffic...)
	}
	return nil
}
