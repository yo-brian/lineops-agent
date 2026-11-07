//go:build !linux

package release

import (
	"context"
	"errors"
)

func (e Engine) LifecycleReconcile(context.Context, LifecycleReconcileRequest) (LifecycleObservation, error) {
	return LifecycleObservation{}, errors.New("linux_required")
}
