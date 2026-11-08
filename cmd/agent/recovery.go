package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"lineops-agent/internal/agentconfig"
	"lineops-agent/internal/release"
	"os"
	"time"
)

func isRecoveryCommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "init", "apply", "recover", "scan", "policy", "trial", "gate", "verify", "receipt", "arm-policy", "reconcile", "probe":
		return true
	case "status":
		return len(args) > 1
	default:
		return false
	}
}

func runRecovery(args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Println("lineops-recovery <init|apply|recover|scan|policy|status|verify|receipt|gate|arm-policy|reconcile|trial|probe> [flags]")
		return nil
	}
	if len(args) < 1 {
		return errors.New("command required; use --help for supported commands")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	configFile := f.String("config", "", "shared Agent YAML config")
	root := f.String("root", "/etc/lineops/instances", "root-owned instance registrations")
	id := f.String("instance", "", "stable instance ID")
	input := f.String("input", "", "local restricted JSON input file")
	task := f.String("task", "", "expected task ID")
	fence := f.Uint64("fencing", 0, "expected fencing")
	binary := f.String("binary", "", "registered sing-box binary (isolated trial or protocol probe)")
	versionDir := f.String("version-dir", "", "immutable version directory (probe/trial)")
	hostNetwork := f.String("host-network", "", "host namespace witness (internal trial only)")
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if len(f.Args()) != 0 {
		return errors.New("unexpected arguments")
	}
	var paths agentconfig.Paths
	configExplicit := false
	rootExplicit := false
	f.Visit(func(fl *flag.Flag) {
		if fl.Name == "config" {
			configExplicit = true
		}
		if fl.Name == "root" {
			rootExplicit = true
		}
	})
	if args[0] != "trial" && args[0] != "probe" {
		if *configFile == "" && !rootExplicit {
			if _, e := os.Stat(agentconfig.DefaultFile); e == nil {
				*configFile = agentconfig.DefaultFile
			}
		}
		if *configFile != "" {
			c, e := agentconfig.Load(*configFile)
			if e != nil {
				if configExplicit {
					return e
				}
				paths = agentconfig.NewPaths()
			} else {
				paths = c.Paths
				*root = paths.InstancesDir
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	engine := release.Engine{Root: *root, Paths: paths, Runtime: release.SystemdRuntime{}}
	switch args[0] {
	case "init":
		r, err := release.ReadRuntime(*input)
		if err != nil {
			return err
		}
		return release.Initialize(ctx, *root, r)
	case "apply":
		r, err := release.ReadRequest(*input)
		if err != nil {
			return err
		}
		state, err := engine.Apply(ctx, r)
		_ = json.NewEncoder(os.Stdout).Encode(state)
		return err
	case "recover":
		state, err := engine.Recover(ctx, *id, *task, *fence, false)
		_ = json.NewEncoder(os.Stdout).Encode(state)
		return err
	case "scan":
		results := engine.Scan(ctx)
		_ = json.NewEncoder(os.Stdout).Encode(results)
		for _, s := range results {
			if s == "failed_manual" || s == "policy_reconciliation_failed" || s == "invalid_registration" || s == "unavailable" {
				return errors.New("one or more instances require operator reconciliation")
			}
		}
		return nil
	case "policy":
		p, err := release.ReadPolicies(*input)
		if err != nil {
			return err
		}
		state, err := engine.UpdatePolicies(ctx, *id, p)
		_ = json.NewEncoder(os.Stdout).Encode(state)
		return err
	case "status":
		state, err := engine.Status(*id)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(state)
	case "trial":
		return release.TrialLocal(ctx, *binary, *versionDir, *hostNetwork)
	case "gate":
		return engine.StartGate(*id)
	case "verify":
		state, err := engine.VerifyStatus(ctx, *id)
		_ = json.NewEncoder(os.Stdout).Encode(state)
		return err
	case "receipt":
		state, err := engine.Receipt(*id, *task)
		_ = json.NewEncoder(os.Stdout).Encode(state)
		return err
	case "arm-policy":
		return release.ArmPolicy(ctx, *root, *id)
	case "reconcile":
		state, err := engine.ReconcilePolicy(ctx, *id)
		_ = json.NewEncoder(os.Stdout).Encode(state)
		return err
	case "probe":
		return release.ProbeVersion(ctx, *versionDir, *binary)
	default:
		return errors.New("unsupported command")
	}
}

func startBackgroundRecoveryScan(ctx context.Context, paths agentconfig.Paths) {
	if os.Geteuid() != 0 {
		return
	}
	if paths.InstancesDir == "" {
		paths = agentconfig.NewPaths()
	}
	engine := release.Engine{Root: paths.InstancesDir, Paths: paths, Runtime: release.SystemdRuntime{}}
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				scanCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				_ = engine.Scan(scanCtx)
				cancel()
			}
		}
	}()
}
