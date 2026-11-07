//go:build !linux

package agent

func syncDirectory(string) error { return nil }
