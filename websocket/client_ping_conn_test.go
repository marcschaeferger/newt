package websocket

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestStalePingMonitorStaysOnItsOwnConnection publishes a second connection
// while the first one is still alive. The ping monitor of the first
// connection must keep pinging that connection only, and a failed ping write
// on it must not close or unpublish the newer connection.
func TestStalePingMonitorStaysOnItsOwnConnection(t *testing.T) {
	setupClientTest(t)

	type serverConn struct {
		pings  chan struct{} // one entry per "newt/ping" received
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
		sc := serverConn{pings: make(chan struct{}, 1024), closed: make(chan struct{})}
		go func() {
			defer close(sc.closed)
			for {
				_, p, err := conn.ReadMessage()
				if err != nil {
					return
				}
				var msg WSMessage
				if json.Unmarshal(p, &msg) == nil && msg.Type == "newt/ping" {
					select {
					case sc.pings <- struct{}{}:
					default:
					}
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
		pingInterval:      20 * time.Millisecond,
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
	published := func() *websocket.Conn {
		client.writeMux.Lock()
		defer client.writeMux.Unlock()
		return client.conn
	}

	if err := client.establishConnection(); err != nil {
		t.Fatalf("first establishConnection: %v", err)
	}
	first := waitAccepted()
	older := published()

	if err := client.establishConnection(); err != nil {
		t.Fatalf("second establishConnection: %v", err)
	}
	second := waitAccepted()
	newer := published()

	// Let pings sent before the second connection was published drain, then
	// require the first connection's monitor to keep pinging its own conn.
	time.Sleep(100 * time.Millisecond)
	for len(first.pings) > 0 {
		<-first.pings
	}
	select {
	case <-first.pings:
	case <-time.After(2 * time.Second):
		t.Fatal("ping monitor of the older connection stopped pinging it once a newer connection was published")
	}

	// Make every further ping write on the older connection fail while its
	// read pump stays up, so its monitor runs into the ping-failure path.
	tcp, ok := older.NetConn().(*net.TCPConn)
	if !ok {
		t.Fatalf("unexpected net.Conn type %T", older.NetConn())
	}
	if err := tcp.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	select {
	case <-first.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("older connection did not shut down")
	}

	select {
	case <-second.closed:
		t.Fatal("stale ping monitor closed the newer connection")
	case <-accepted:
		t.Fatal("stale ping monitor caused a reconnect although a newer connection is live")
	case <-time.After(300 * time.Millisecond):
	}
	if current := published(); current != newer {
		t.Fatalf("published connection changed after stale ping failure: got %p, want %p", current, newer)
	}
}
