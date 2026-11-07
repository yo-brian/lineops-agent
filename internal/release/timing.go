package release

import (
	"log"
	"time"
)

// Do not log configurations, addresses, credentials or raw runtime errors.
func timedStage(task, stage string, run func() error) error {
	start := time.Now()
	err := run()
	log.Printf("release_timing task=%q stage=%s elapsed_ms=%d success=%t", task, stage, time.Since(start).Milliseconds(), err == nil)
	return err
}
