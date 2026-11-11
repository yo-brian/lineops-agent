//go:build !linux && !darwin

package release

import (
	"context"
	"errors"
	"lineops-agent/internal/traffic"
)

func (e Engine) Traffic(context.Context, string) ([]traffic.Sample, error) {
	return nil, errors.New("traffic requires Linux")
}
