//go:build !linux && !darwin

package agent

import "lineops-agent/internal/traffic"

func hostTraffic() []traffic.Sample { return nil }
