package netstack2

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
)

// TestHTTPRequestLogger_FailingSendDoesNotResendPerRequest verifies that while
// the server keeps rejecting batches, logging more requests does not trigger a
// compress-and-send of the whole buffer for every single request, and that the
// buffer cap keeps the newest entries.
func TestHTTPRequestLogger_FailingSendDoesNotResendPerRequest(t *testing.T) {
	rl := NewHTTPRequestLogger()
	defer rl.Close()

	var attempts atomic.Int64
	rl.SetSendFunc(func(string) error {
		attempts.Add(1)
		return errors.New("server unavailable")
	})

	const total = 1000
	for i := 0; i < total; i++ {
		rl.LogRequest(HTTPRequestLog{RequestID: fmt.Sprintf("req-%d", i)})
	}

	if got := attempts.Load(); got > 20 {
		t.Fatalf("send attempted %d times for %d logged requests while failing; want <= 20", got, total)
	}

	newest := fmt.Sprintf("req-%d", total-1)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if n := len(rl.pending); n > maxBufferedSessions*5 {
		t.Fatalf("pending buffer has %d entries; want <= %d", n, maxBufferedSessions*5)
	}
	found := false
	for _, l := range rl.pending {
		if l.RequestID == newest {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("newest request %q was not retained in the pending buffer", newest)
	}
}
