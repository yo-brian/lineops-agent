//go:build linux

package release

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Exercises the actual signed-release core, including the upstream gRPC service
// name, lazy counters, closed connections and non-destructive repeated reads.
func TestSingboxNativeTraffic(t *testing.T) {
	binary := os.Getenv("LINEOPS_SINGBOX_STATS_BINARY")
	if binary == "" {
		t.Skip("set LINEOPS_SINGBOX_STATS_BINARY to the stats-enabled 1.14.0 build")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(reserve.Addr().(*net.TCPAddr).Port)
	reserve.Close()
	id := "aaaaaaaa-1111-4111-8111-111111111111"
	model := Model{Nodes: []Node{{ID: id, Listen: "127.0.0.1", Port: port, ProtocolOptions: ProtocolOptions{RelayAddress: "127.0.0.1", RelayPort: uint16(upstream.Addr().(*net.TCPAddr).Port)}}}}
	raw, err := Render(model, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw, err = addTrafficAPI(raw, id, model)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
	var logs bytes.Buffer
	cmd.Stderr = &logs
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	listener := trafficListener(id, model)
	endpoint := net.JoinHostPort(listener.Listen, strconv.Itoa(int(listener.Port)))
	var counters map[string]uint64
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		counters, err = querySingboxTraffic(ctx, endpoint)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("%v %s", err, logs.String())
	}
	if len(counters) != 0 {
		t.Fatal("expected lazy zero counters", counters)
	}
	done := make(chan error, 1)
	go func() {
		c, e := upstream.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		_, e = io.ReadFull(c, make([]byte, 1024))
		if e == nil {
			_, e = c.Write(make([]byte, 8192))
		}
		done <- e
	}()
	client, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = client.Write(make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadFull(client, make([]byte, 8192)); err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		counters, err = querySingboxTraffic(ctx, endpoint)
		if err != nil {
			t.Fatal(err)
		}
		samples := singboxSamples(model, "test", counters, time.Now())
		if samples[0].Upload != 1024 || samples[0].Download != 8192 {
			t.Fatal(samples, counters)
		}
	}
}
