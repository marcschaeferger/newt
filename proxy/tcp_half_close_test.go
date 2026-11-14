package proxy

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/telemetry"
)

// TestTCPProxyPreservesHalfClose verifies that when a client half-closes its
// side of a proxied TCP connection (CloseWrite), the proxy forwards the FIN to
// the backend while keeping the return path open, so a backend that reads
// until EOF before replying can still deliver its response to the client.
func TestTCPProxyPreservesHalfClose(t *testing.T) {
	if _, err := telemetry.Init(context.Background(), telemetry.Config{ServiceName: "test"}); err != nil {
		t.Fatalf("telemetry.Init: %v", err)
	}

	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("backend Listen: %v", err)
	}
	defer backend.Close()

	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		data, err := io.ReadAll(c)
		if err != nil {
			return
		}
		_, _ = c.Write(append([]byte("echo:"), data...))
	}()

	// Reserve a free port for the proxy listener.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe Listen: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()

	pm := NewProxyManagerNative("127.0.0.1")
	if err := pm.AddTarget("tcp", "127.0.0.1", port, backend.Addr().String()); err != nil {
		t.Fatalf("AddTarget: %v", err)
	}
	if err := pm.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer pm.Stop()

	conn, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("Dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll: %v (received %q)", err, got)
	}
	if string(got) != "echo:hello" {
		t.Fatalf("client received %q, want %q: proxy did not preserve TCP half-close", got, "echo:hello")
	}
}
