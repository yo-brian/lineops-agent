package agent

import (
	"context"
	"slices"
	"strings"

	"lineops-agent/internal/agentproto"
	"lineops-agent/internal/traffic"
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
	if err != nil && (optimized || inventory.FRPLifecycle || inventory.FRPStatus != nil) && (code == 400 || code == 409 || code == 415) {
		// Covers lost acknowledgements, server restore and mixed-version rollout.
		c.heartbeatGzip = false
		c.heartbeatDelta = false
		c.acknowledgedTraffic = nil
		c.cachedInstancesValid = false
		ack = agentproto.HeartbeatAck{}
		fallbackInv := inventory
		if code == 400 {
			fallbackInv.FRPLifecycle = false
			fallbackInv.FRPStatus = nil
		}
		full := agentproto.Heartbeat{Inventory: fallbackInv, InstancePartial: partial, InstanceTrafficObserved: payload.InstanceTrafficObserved}
		_, err = c.request(ctx, "POST", "/heartbeat", full, &ack)
	}
	if err != nil {
		c.cachedInstancesValid = false
		return err
	}
	c.heartbeatGzip = slices.Contains(ack.Capabilities, agentproto.HeartbeatGzip)
	c.heartbeatDelta = slices.Contains(ack.Capabilities, agentproto.HeartbeatDelta)
	c.acknowledgedTraffic = nil
	if ack.TrafficHash == agentproto.TrafficHash(inventory.NodeTraffic) {
		c.acknowledgedTraffic = append([]traffic.Sample(nil), inventory.NodeTraffic...)
	}
	if ack.InstancesComplete && len(ack.InstanceIDs) <= 100 {
		valid := true
		for i, id := range ack.InstanceIDs {
			if len(id) != 36 || strings.ContainsAny(id, "/\\.") || (i > 0 && id <= ack.InstanceIDs[i-1]) {
				valid = false
				break
			}
		}
		if valid {
			c.cachedInstanceIDs = append([]string(nil), ack.InstanceIDs...)
			c.cachedInstancesValid = true
		} else {
			c.cachedInstancesValid = false
		}
	} else {
		c.cachedInstancesValid = false
	}
	return nil
}
