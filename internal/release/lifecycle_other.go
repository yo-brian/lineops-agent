//go:build !linux && !darwin

package release

import (
	"context"
	"errors"
)

func (e Engine) Lifecycle(context.Context, LifecycleRequest) (LifecycleResult, error) {
	return LifecycleResult{}, errors.New("linux_required")
}
func (e Engine) LifecycleReceipt(LifecycleRequest) (LifecycleResult, error) {
	return LifecycleResult{}, errors.New("linux_required")
}
