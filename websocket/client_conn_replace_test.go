package websocket

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestStaleReadPumpDoesNotTearDownNewerConnection publishes a second
// connection while the read pump of the first one is still running, then
// drops the first connection server-side. The stale pump's cleanup and
// reconnect must only affect its own connection: the newer connection has to
// stay published and open.
func TestStaleReadPumpDoesNotTearDownNewerConnection(t *testing.T) {
	setupClientTest(t)

	type serverConn struct {
		conn   *websocket.Conn
		closed chan struct{} // closed once the client side has gone away
	}
	accepted := make(chan serverConn, 8)

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
		sc := serverConn{conn: conn, closed: make(chan struct{})}
		go func() {
			defer close(sc.closed)
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
		accepted <- sc
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
	defer client.Close()

	waitAccepted := func() serverConn {
		t.Helper()
		select {
		case sc := <-accepted:
			return sc
		case <-time.After(5 * time.Second):
			t.Fatal("server did not accept a websocket connection")
			return serverConn{}
		}
	}

	if err := client.establishConnection(); err != nil {
		t.Fatalf("first establishConnection: %v", err)
	}
	first := waitAccepted()

	if err := client.establishConnection(); err != nil {
		t.Fatalf("second establishConnection: %v", err)
	}
	second := waitAccepted()

	client.writeMux.Lock()
	newer := client.conn
	client.writeMux.Unlock()

	// Drop the first connection; its read pump now runs cleanup and reconnect.
	_ = first.conn.Close()
	select {
	case <-first.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("first connection did not shut down")
	}

	select {
	case <-second.closed:
		t.Fatal("stale read pump closed the newer connection")
	case sc := <-accepted:
		_ = sc.conn.Close()
		t.Fatal("stale read pump started a reconnect although a newer connection is live")
	case <-time.After(300 * time.Millisecond):
	}

	client.writeMux.Lock()
	current := client.conn
	client.writeMux.Unlock()
	if current != newer {
		t.Fatalf("published connection changed after stale pump exit: got %p, want %p", current, newer)
	}
}
