package newt

import (
	"context"
	"testing"

	"github.com/fosrl/newt/internal/telemetry"
	"github.com/fosrl/newt/websocket"
)

// TestHandleConnectReleasesTunnelOnEndpointError guards against handleConnect
// leaking the freshly created WireGuard device and netstack TUN when the
// endpoint cannot be parsed or resolved. A leaked device kept running while
// n.connected stayed false, so the next registration silently overwrote it.
func TestHandleConnectReleasesTunnelOnEndpointError(t *testing.T) {
	if _, err := telemetry.Init(context.Background(), telemetry.Config{ServiceName: "test"}); err != nil {
		t.Fatalf("telemetry.Init: %v", err)
	}

	tests := []struct {
		name     string
		endpoint string
	}{
		{name: "endpoint without port", endpoint: "no-port-here"},
		{name: "unresolvable endpoint", endpoint: "pangolin.invalid:51820"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Newt{config: Config{DNS: "9.9.9.9", MTU: 1280}}
			t.Cleanup(func() {
				// Release anything the code under test leaked so the
				// failing case does not bleed into other tests.
				if n.dev != nil {
					n.dev.Close()
				} else if n.tun != nil {
					_ = n.tun.Close()
				}
			})

			n.handleConnect(context.Background(), websocket.WSMessage{
				Type: "newt/wg/connect",
				Data: map[string]any{
					"endpoint":  tt.endpoint,
					"publicKey": "",
					"serverIP":  "100.89.128.1",
					"tunnelIP":  "100.89.128.4",
				},
			})

			if n.connected {
				t.Fatal("connected = true after failed registration, want false")
			}
			if n.dev != nil {
				t.Error("WireGuard device left open after failed registration")
			}
			if n.tun != nil {
				t.Error("TUN device left open after failed registration")
			}
			if n.tnet != nil {
				t.Error("netstack left set after failed registration")
			}
		})
	}
}
