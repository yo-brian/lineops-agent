package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/term"
	"lineops-agent/internal/agent"
	"lineops-agent/internal/agentconfig"
	"lineops-agent/internal/agentmenu"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func main() {
	if strings.HasPrefix(filepath.Base(os.Args[0]), "lineops-recovery") || isRecoveryCommand(os.Args[1:]) {
		if err := runRecovery(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, "lineops-recovery:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 1 || (len(os.Args) == 2 && os.Args[1] == "menu") {
		if err := agentmenu.Run(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) == 2 && !strings.HasPrefix(os.Args[1], "-") {
		if err := agentmenu.Command(os.Args[1]); err != nil {
			log.Fatal(err)
		}
		return
	}
	configFile := flag.String("config", "", "YAML configuration file")
	printConfig := flag.Bool("print-config", false, "validate config and print resolved JSON without credentials")
	panel := flag.String("panel", "", "HTTPS panel origin")
	state := flag.String("state-dir", "/var/lib/lineops-agent", "protected state directory")
	ca := flag.String("ca-file", "", "optional trusted test/private CA")
	enroll := flag.Bool("enroll", false, "read single-use registration token from stdin")
	inventory := flag.Bool("inventory", false, "print local read-only inventory and exit")
	once := flag.Bool("once", false, "send one heartbeat and poll once")
	rotate := flag.Bool("rotate", false, "durably rotate identity with resumable confirmation and exit")
	executorSocket := flag.String("executor-socket", "", "optional root-owned Unix socket for explicitly registered managed instances")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "交互管理：sudo lineops-agent（或 lineops-agent menu）\n快捷命令：config、status、log、singbox-log、singbox-restart、start、stop、restart、enable、disable、bbr、unbind\nconfig 配置面板地址/API Key/节点绑定；start/stop/restart/enable/disable 只操作 Agent；singbox-restart 重启 sing-box 实例；unbind 解除面板绑定并保留节点。\n后台 Agent 参数：")
		flag.PrintDefaults()
	}
	flag.Parse()
	var cfg *agentconfig.Config
	if *configFile == "" {
		if _, e := os.Stat(agentconfig.DefaultFile); e == nil {
			*configFile = agentconfig.DefaultFile
		} else if !os.IsNotExist(e) {
			log.Fatal(e)
		}
	}
	if *configFile != "" {
		loaded, e := agentconfig.Load(*configFile)
		if e != nil {
			log.Fatal(e)
		}
		cfg = &loaded
		supplied := map[string]bool{}
		flag.Visit(func(f *flag.Flag) { supplied[f.Name] = true })
		for _, name := range []string{"panel", "state-dir", "ca-file", "executor-socket"} {
			if supplied[name] {
				log.Fatal("--config cannot be combined with connection/path overrides")
			}
		}
		*panel = cfg.Panel.URL
		*state = cfg.Paths.AgentStateDir
		*ca = cfg.Panel.CAFile
		*executorSocket = cfg.Paths.ExecutorSocket
	}
	if *printConfig {
		if cfg == nil {
			log.Fatal("--print-config requires a config file")
		}
		json.NewEncoder(os.Stdout).Encode(cfg.Redacted())
		return
	}
	if *inventory {
		json.NewEncoder(os.Stdout).Encode(agent.Inventory())
		return
	}
	if runtime.GOOS != "linux" {
		log.Fatal("Agent service only supports Linux; Windows build is not an installation target")
	}
	c, err := agent.New(*panel, *state, *ca)
	if err != nil {
		log.Fatal(err)
	}
	var paths agentconfig.Paths
	if cfg != nil {
		paths = cfg.Paths
	}
	if err = c.ConfigureAutoExecutor(*executorSocket, paths); err != nil {
		log.Fatal(err)
	}
	if cfg != nil {
		c.EnrollmentMode = cfg.Enrollment.Mode
		c.StaticCredential = cfg.Credential()
		if !cfg.HasStaticCredential() {
			c.StaticCredential = ""
		}
		if err = c.ConfigureBinding(cfg.Binding); err != nil {
			log.Fatal(err)
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *rotate {
		if err = c.Rotate(ctx); err != nil {
			log.Fatal(err)
		}
		log.Print("Identity rotation confirmed and persisted")
		return
	}
	if cfg != nil && !c.HasIdentity() && !*enroll {
		token := cfg.Credential()
		if token == "" {
			log.Fatal("no Agent identity; supply api_key in config.yml, enrollment token via configured environment variable, or --enroll stdin")
		}
		if err = c.Enroll(ctx, token); err != nil {
			if cfg.HasStaticCredential() && !*once {
				log.Printf("initial API key enrollment deferred (will retry in loop): %v", err)
			} else {
				log.Fatal(err)
			}
		}
	}
	if *enroll {
		var token string
		if cfg != nil && cfg.HasStaticCredential() {
			token = cfg.Credential()
		} else {
			fmt.Fprint(os.Stderr, "Registration token (stdin; do not put in command arguments): ")
			if term.IsTerminal(int(os.Stdin.Fd())) {
				data, e := term.ReadPassword(int(os.Stdin.Fd()))
				err = e
				token = string(data)
				fmt.Fprintln(os.Stderr)
			} else {
				token, err = bufio.NewReader(os.Stdin).ReadString('\n')
			}
			if err != nil && token == "" {
				log.Fatal("registration input unavailable")
			}
		}
		if err = c.Enroll(ctx, token); err != nil {
			log.Fatal(err)
		}
		log.Print("Identity registered and persisted; awaiting real heartbeat")
	}
	if cfg != nil && c.HasIdentity() {
		if err = c.ValidateBinding(ctx); err != nil {
			if cfg.HasStaticCredential() && !*once {
				log.Printf("binding check deferred (will retry in loop): %v", err)
			} else {
				log.Fatal(err)
			}
		}
	}
	if *once {
		failed := false
		if err = c.Heartbeat(ctx); err != nil {
			log.Print(err)
			failed = true
		}
		if err = c.Poll(ctx); err != nil {
			log.Print(err)
			failed = true
		}
		if failed {
			os.Exit(1)
		}
		return
	}
	startBackgroundRecoveryScan(ctx, paths)
	runLoop(ctx, c.Heartbeat, c.Poll, func(err error) { log.Print(err) }, 5*time.Second, 15*time.Second)
}
