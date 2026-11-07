//go:build !linux

package agent

import "lineops-agent/internal/traffic"

func hostTraffic() []traffic.Sample { return nil }
