package main

import (
	"context"
	"time"
)

// Serialize client operations: identity rotation and durable receipt recovery
// must not race with heartbeats. Separate schedules avoid collecting inventory
// before every command poll. The initial heartbeat establishes readiness.
func runLoop(ctx context.Context, heartbeat, poll func(context.Context) error, report func(error), pollEvery, heartbeatEvery time.Duration) {
	if ctx.Err() != nil {
		return
	}
	call := func(fn func(context.Context) error) {
		if err := fn(ctx); err != nil && ctx.Err() == nil {
			report(err)
		}
	}
	call(heartbeat)
	nextHeartbeat := time.Now().Add(heartbeatEvery)
	nextPoll := time.Now()
	for ctx.Err() == nil {
		if !time.Now().Before(nextPoll) {
			call(poll)
			nextPoll = time.Now().Add(pollEvery)
		}
		if ctx.Err() != nil {
			return
		}
		if !time.Now().Before(nextHeartbeat) {
			call(heartbeat)
			nextHeartbeat = time.Now().Add(heartbeatEvery)
		}
		next := nextPoll
		if nextHeartbeat.Before(next) {
			next = nextHeartbeat
		}
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
