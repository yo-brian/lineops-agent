//go:build !linux

package agent

import "lineop-agent/internal/traffic"

func hostTraffic() []traffic.Sample { return nil }
