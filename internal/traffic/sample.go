// Package traffic contains bounded counter observations, not billing records.
package traffic

import "time"

type Sample struct {
	ResourceID string    `json:"resource_id,omitempty"`
	Source     string    `json:"source"`
	Upload     uint64    `json:"upload"`
	Download   uint64    `json:"download"`
	ObservedAt time.Time `json:"observed_at"`
}

func (s Sample) Valid() bool {
	return len(s.ResourceID) <= 36 && len(s.Source) > 0 && len(s.Source) <= 128 && s.Upload < 1<<60 && s.Download < 1<<60 && !s.ObservedAt.IsZero()
}

// Delta ignores replayed observations and establishes a new baseline after a
// counter reset. It never interprets a reset as an unsigned counter wrap.
func Delta(previous, current uint64) uint64 {
	if current < previous {
		return 0
	}
	return current - previous
}
