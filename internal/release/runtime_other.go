//go:build !linux

package release

import (
	"context"
	"errors"
	"os"
)

type SystemdRuntime struct{}

func unsupported() error                                                  { return errors.New("controlled release requires Linux systemd") }
func (SystemdRuntime) Check(context.Context, RuntimeConfig, string) error { return unsupported() }
func (SystemdRuntime) Trial(context.Context, RuntimeConfig, string) error { return unsupported() }
func (SystemdRuntime) Guard(context.Context, RuntimeConfig, string, Journal) error {
	return unsupported()
}
func (SystemdRuntime) Restart(context.Context, RuntimeConfig, string) error { return unsupported() }
func (SystemdRuntime) Stop(context.Context, RuntimeConfig) error            { return unsupported() }
func (SystemdRuntime) Healthy(context.Context, RuntimeConfig, string, Model) error {
	return unsupported()
}
func Initialize(context.Context, string, RuntimeConfig) error { return unsupported() }
func ArmPolicy(context.Context, string, string) error         { return unsupported() }
func isolatedNetwork(string) (bool, error)                    { return false, unsupported() }
func processAlive(*os.Process) bool                           { return false }
