package newt

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/fosrl/newt/healthcheck"
	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/websocket"
	gws "github.com/gorilla/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// fakeControlPlane is a minimal Pangolin websocket endpoint. For every
// newt/ping/request it asks pingReply what to answer; it records every real
// (non backwards-compatible) newt/wg/register it receives.
type fakeControlPlane struct {
	// pingReply returns the exit nodes to send for a ping request, or nil to
	// stay silent. conn counts websocket connections from 1.
	pingReply func(conn int, chainID string) []map[string]any
	// dropAfterFirstPing closes the first websocket connection once a ping
	// request arrived on it, forcing a reconnect.
	dropAfterFirstPing bool

	mu        sync.Mutex
	conns     int
	registers chan struct{}
}

var oneExitNode = []map[string]any{{"exitNodeId": 1, "exitNodeName": "a", "endpoint": "127.0.0.1:9", "weight": 1}}

func (f *fakeControlPlane) serve(t *testing.T) *httptest.Server {
	t.Helper()
	f.registers = make(chan struct{}, 64)
	upgrader := gws.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/newt/get-token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"data":{"token":"tok","serverVersion":""}}`))
	})
	mux.HandleFunc("/api/v1/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		f.mu.Lock()
		f.conns++
		conn := f.conns
		f.mu.Unlock()
		for {
			_, p, err := c.ReadMessage()
			if err != nil {
				return
			}
			var m struct {
				Type string         `json:"type"`
				Data map[string]any `json:"data"`
			}
			if err := json.Unmarshal(p, &m); err != nil {
				continue
			}
			switch m.Type {
			case "newt/ping/request":
				chainID, _ := m.Data["chainId"].(string)
				if nodes := f.pingReply(conn, chainID); nodes != nil {
					_ = c.WriteJSON(map[string]any{
						"type": "newt/ping/exitNodes",
						"data": map[string]any{"exitNodes": nodes, "chainId": chainID},
					})
				}
				if f.dropAfterFirstPing && conn == 1 {
					return
				}
			case "newt/wg/register":
				if bc, _ := m.Data["backwardsCompatible"].(bool); !bc {
					select {
					case f.registers <- struct{}{}:
					default:
					}
				}
			}
		}
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// startNewt wires a Newt with handlers to the fake control plane. Connect is
// left to the caller so it can prepare state first.
func startNewt(t *testing.T, srv *httptest.Server) *Newt {
	t.Helper()
	if err := telemetry.EnsureInstruments(); err != nil {
		t.Fatal(err)
	}
	client, err := websocket.NewClient("newt", "id", "secret", srv.URL, 30*time.Second,
		websocket.WithConfigFile(filepath.Join(t.TempDir(), "config.json")))
	if err != nil {
		t.Fatal(err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	n := &Newt{client: client, privateKey: key, publicKey: key.PublicKey()}
	ctx, cancel := context.WithCancel(context.Background())
	n.registerHandlers(ctx)
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
	})
	return n
}

func waitForRegister(t *testing.T, f *fakeControlPlane, within time.Duration, why string) {
	t.Helper()
	select {
	case <-f.registers:
	case <-time.After(within):
		t.Fatalf("no newt/wg/register within %v: %s", within, why)
	}
}

// An empty exit-node list (e.g. Pangolin still starting up) must not end the
// registration for good: newt has to ask again after a backoff.
func TestRegisterChainRetriesAfterEmptyExitNodeList(t *testing.T) {
	var mu sync.Mutex
	replies := 0
	f := &fakeControlPlane{pingReply: func(_ int, _ string) []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		replies++
		if replies == 1 {
			return []map[string]any{}
		}
		return oneExitNode
	}}
	srv := f.serve(t)
	n := startNewt(t, srv)
	setChainTiming(n, time.Second, time.Second, 100*time.Millisecond, 400*time.Millisecond)
	if err := n.client.Connect(); err != nil {
		t.Fatal(err)
	}
	waitForRegister(t, f, 4*time.Second, "an empty exit-node list ended the chain without a retry")
}

// A control plane that does not answer until the ping-request chain has used
// up its SendMessageInterval attempts must still get a registration once it
// answers again.
func TestRegisterChainRestartsAfterPingRequestAttemptsExhausted(t *testing.T) {
	var mu sync.Mutex
	var firstChain string
	f := &fakeControlPlane{pingReply: func(_ int, chainID string) []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		if firstChain == "" {
			firstChain = chainID
		}
		if chainID == firstChain {
			return nil // overloaded: drop every attempt of the first chain
		}
		return oneExitNode
	}}
	srv := f.serve(t)
	n := startNewt(t, srv)
	setChainTiming(n, 20*time.Millisecond, 20*time.Millisecond, 100*time.Millisecond, 400*time.Millisecond)
	if err := n.client.Connect(); err != nil {
		t.Fatal(err)
	}
	waitForRegister(t, f, 4*time.Second, "the exhausted ping-request chain was never restarted")
}

// Data-plane recovery latches connectionLost while the websocket stays
// connected. A websocket reconnect during that state must request exit nodes
// again instead of treating the dead tunnel as connected.
func TestRegisterChainRestartsOnWebsocketReconnectDuringRecovery(t *testing.T) {
	var mu sync.Mutex
	seenOnFirstConn := map[string]bool{}
	f := &fakeControlPlane{
		dropAfterFirstPing: true,
		pingReply: func(conn int, chainID string) []map[string]any {
			mu.Lock()
			defer mu.Unlock()
			if conn == 1 {
				seenOnFirstConn[chainID] = true
				return nil
			}
			if seenOnFirstConn[chainID] {
				return nil // only a chain started after the reconnect counts
			}
			return oneExitNode
		},
	}
	srv := f.serve(t)
	n := startNewt(t, srv)
	// Keep the supervisor slow so that only the reconnect can start a chain.
	setChainTiming(n, time.Second, time.Second, time.Minute, time.Minute)
	n.config.PingInterval = 20 * time.Millisecond
	n.config.PingTimeout = 10 * time.Millisecond
	n.healthMonitor = healthcheck.NewMonitor(func(map[int]*healthcheck.Target) {}, false)
	t.Cleanup(n.healthMonitor.Stop)
	// An established tunnel whose data plane is dead.
	n.connected = true
	if err := n.client.Connect(); err != nil {
		t.Fatal(err)
	}
	dead := func(string, time.Duration) (time.Duration, error) { return 0, errors.New("unreachable") }
	stop := n.startPingCheck(dead, "100.89.128.1", "")
	t.Cleanup(func() { close(stop) })

	waitForRegister(t, f, 5*time.Second, "websocket reconnect did not restart the chain while recovery was latched")
}
