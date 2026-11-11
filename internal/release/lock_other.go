//go:build !linux && !darwin

package release

import (
	"context"
	"errors"
)

func syncDir(string) error { return errors.New("durable publication requires Linux") }
func acquire(context.Context, string) (func(), error) {
	return nil, errors.New("OS publication locking requires Linux")
}
func bootID() string { return "unsupported" }
