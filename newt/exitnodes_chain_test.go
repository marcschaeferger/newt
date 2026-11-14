package newt

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/websocket"
	gws "github.com/gorilla/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// A duplicate newt/ping/exitNodes reply carrying an already consumed chainId
// must be discarded without cancelling the newt/wg/register retry chain that
// the first (accepted) reply started.
func TestDuplicateExitNodesReplyKeepsRegisterRetrying(t *testing.T) {
	if err := telemetry.EnsureInstruments(); err != nil {
		t.Fatal(err)
	}

	var registers atomic.Int32
	registered := make(chan struct{}, 16)

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
		answered := false
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
				if answered {
					continue
				}
				answered = true
				chainID, _ := m.Data["chainId"].(string)
				reply := map[string]any{
					"type": "newt/ping/exitNodes",
					"data": map[string]any{
						"exitNodes": []map[string]any{{"exitNodeId": 1, "exitNodeName": "a", "endpoint": "127.0.0.1:9", "weight": 1}},
						"chainId":   chainID,
					},
				}
				// Same reply twice, as when the server answers both the
				// original request and its retry with the same chainId.
				_ = c.WriteJSON(reply)
				_ = c.WriteJSON(reply)
			case "newt/wg/register":
				if bc, _ := m.Data["backwardsCompatible"].(bool); !bc {
					registers.Add(1)
					registered <- struct{}{}
				}
			}
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := websocket.NewClient("newt", "id", "secret", srv.URL, 30*time.Second,
		websocket.WithConfigFile(filepath.Join(t.TempDir(), "config.json")))
	if err != nil {
		t.Fatal(err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	n := &Newt{client: client, privateKey: key}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	n.registerHandlers(ctx)
	if err := client.Connect(); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// The register interval is 2s; the server never answers with
	// newt/wg/connect, so a live retry chain must send a second register.
	deadline := time.After(5 * time.Second)
	for registers.Load() < 2 {
		select {
		case <-registered:
		case <-deadline:
			t.Fatalf("register retry chain was cancelled by a duplicate exitNodes reply: %d newt/wg/register sent, want >= 2", registers.Load())
		}
	}
}
