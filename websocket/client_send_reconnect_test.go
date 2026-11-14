package websocket

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/logger"
	"github.com/gorilla/websocket"
)

// TestSendMessageDuringReconnectDoesNotPanic drives a client against a server
// that drops every websocket connection shortly after accepting it, so the
// client keeps reconnecting while another goroutine sends messages. A send
// that races the reconnect must return an error rather than dereference a
// nil connection.
func TestSendMessageDuringReconnectDoesNotPanic(t *testing.T) {
	if _, err := telemetry.Init(context.Background(), telemetry.Config{ServiceName: "test"}); err != nil {
		t.Fatalf("telemetry.Init: %v", err)
	}
	// Initialise the global logger before any goroutine uses it; its lazy
	// initialisation is not safe for concurrent first use. Raising the level
	// also keeps the per-send debug line from flooding the test output.
	logger.GetLogger().SetLevel(logger.ERROR)

	upgrader := websocket.Upgrader{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/newt/get-token", func(w http.ResponseWriter, r *http.Request) {
		var resp TokenResponse
		resp.Success = true
		resp.Data.Token = "test-token"
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/api/v1/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		go func() {
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
		time.Sleep(5 * time.Millisecond)
		_ = conn.Close()
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &Client{
		config:            &Config{ID: "id", Secret: "secret", Endpoint: srv.URL},
		baseURL:           srv.URL,
		handlers:          make(map[string]MessageHandler),
		done:              make(chan struct{}),
		reconnectInterval: 10 * time.Millisecond,
		pingInterval:      time.Hour,
		pongWait:          time.Hour,
		clientType:        "newt",
	}
	if err := client.Connect(); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	deadline := time.Now().Add(2 * time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(noLog bool) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if noLog {
					_ = client.SendMessageNoLog("newt/test", map[string]int{"n": 1})
				} else {
					_ = client.SendMessage("newt/test", map[string]int{"n": 1})
				}
			}
		}(i%2 == 0)
	}
	wg.Wait()
}
