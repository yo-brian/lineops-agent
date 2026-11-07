package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLoopPollsWithoutRepeatingInventory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	heartbeat, polls, reports := 0, 0, 0
	runLoop(ctx, func(context.Context) error { heartbeat++; return nil }, func(context.Context) error {
		if heartbeat != 1 {
			t.Error("initial heartbeat missing or inventory repeated")
		}
		polls++
		if polls == 3 {
			cancel()
			return nil
		}
		return errors.New("temporary poll failure")
	}, func(error) { reports++ }, time.Millisecond, time.Hour)
	if polls != 3 || heartbeat != 1 || reports != 2 {
		t.Fatalf("heartbeat=%d polls=%d reports=%d", heartbeat, polls, reports)
	}
}

func TestLoopHeartbeatsWhileIdleAndCancels(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	heartbeats, polls := 0, 0
	runLoop(ctx, func(context.Context) error {
		heartbeats++
		if heartbeats == 3 {
			cancel()
		}
		return nil
	}, func(context.Context) error { polls++; return nil }, func(error) {}, time.Hour, time.Millisecond)
	if heartbeats != 3 || polls != 1 {
		t.Fatalf("heartbeat=%d polls=%d", heartbeats, polls)
	}
}
