package docker

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// newFakeDockerd starts an HTTP server on a unix socket that mimics the
// subset of the Docker Engine API used by EventMonitor. The first /events
// subscription is closed immediately (simulating a dropped stream); every
// later subscription emits one container start event and then stays open.
func newFakeDockerd(t *testing.T) (socket string, subscriptions *atomic.Int32) {
	t.Helper()

	subscriptions = new(atomic.Int32)
	socket = filepath.Join(t.TempDir(), "docker.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen on unix socket: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Api-Version", "1.44")
		switch {
		case r.URL.Path == "/_ping":
			_, _ = w.Write([]byte("OK"))
		case strings.HasSuffix(r.URL.Path, "/events"):
			if subscriptions.Add(1) == 1 {
				// Drop the first stream without sending anything.
				return
			}
			w.Header().Set("Content-Type", "application/x-ndjson")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Type":   "container",
				"Action": "start",
				"Actor":  map[string]any{"ID": "0123456789abcdef0123456789abcdef"},
			})
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("[]"))
		default:
			http.NotFound(w, r)
		}
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)

	return socket, subscriptions
}

func TestEventMonitorResubscribesAfterStreamError(t *testing.T) {
	oldDelay := eventReconnectDelay
	eventReconnectDelay = 10 * time.Millisecond
	t.Cleanup(func() { eventReconnectDelay = oldDelay })

	socket, subscriptions := newFakeDockerd(t)

	called := make(chan struct{}, 1)
	em, err := NewEventMonitor(socket, false, func([]Container) {
		select {
		case called <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatalf("NewEventMonitor: %v", err)
	}
	t.Cleanup(em.Stop)

	if err := em.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	select {
	case <-called:
	case <-time.After(10 * time.Second):
		t.Fatalf("callback never fired after the event stream dropped (subscriptions=%d)", subscriptions.Load())
	}
}
