//go:build !linux && !darwin

package agent

func syncDirectory(string) error { return nil }
