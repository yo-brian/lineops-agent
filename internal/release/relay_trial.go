package release

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strconv"
	"time"
)

// Only called inside TrialLocal's verified private network namespace.
func trialRelayTargets(m *Model) (func(), error) {
	listeners := []net.Listener{}
	cleanup := func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}
	for i := range m.Nodes {
		if m.Nodes[i].RelayAddress == "" {
			continue
		}
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			cleanup()
			return nil, err
		}
		listeners = append(listeners, l)
		m.Nodes[i].RelayAddress = "127.0.0.1"
		m.Nodes[i].RelayPort = uint16(l.Addr().(*net.TCPAddr).Port)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(5 * time.Second))
					_, _ = io.Copy(c, io.LimitReader(c, 64))
				}()
			}
		}()
	}
	return cleanup, nil
}

func probeTrialRelays(ctx context.Context, m Model) error {
	for _, n := range m.Nodes {
		if n.RelayAddress == "" {
			continue
		}
		nonce := make([]byte, 64)
		if _, err := rand.Read(nonce); err != nil {
			return err
		}
		deadline := time.Now().Add(5 * time.Second)
		verified := false
		for time.Now().Before(deadline) && ctx.Err() == nil {
			c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(n.Listen, strconv.Itoa(int(n.Port))))
			if err == nil {
				_ = c.SetDeadline(deadline)
				_, err = c.Write(nonce)
				got := make([]byte, len(nonce))
				if err == nil {
					_, err = io.ReadFull(c, got)
				}
				c.Close()
				if err == nil && bytes.Equal(nonce, got) {
					verified = true
					break
				}
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if !verified {
			return errors.New("isolated TCP relay round-trip failed")
		}
	}
	return nil
}
