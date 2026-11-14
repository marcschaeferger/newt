package newt

import (
	"testing"

	"github.com/fosrl/newt/healthcheck"
	"github.com/fosrl/newt/proxy"
	"github.com/fosrl/newt/websocket"
)

func TestHandleSyncKeepsDesiredIPv6Targets(t *testing.T) {
	const tunnelIP = "100.89.128.2"

	pm := proxy.NewProxyManagerWithoutTNet()
	n := &Newt{
		pm:            pm,
		wgData:        WgData{TunnelIP: tunnelIP},
		healthMonitor: healthcheck.NewMonitor(nil, false),
	}

	tcpTargets := []string{"8443:[fd00::10]:443", "8080:10.0.0.5:80"}
	udpTargets := []string{"5353:[fd00::53]:53", "5354:10.0.0.53:53"}

	if err := n.updateTargets(pm, "add", tunnelIP, "tcp", TargetData{Targets: tcpTargets}); err != nil {
		t.Fatalf("add tcp targets: %v", err)
	}
	if err := n.updateTargets(pm, "add", tunnelIP, "udp", TargetData{Targets: udpTargets}); err != nil {
		t.Fatalf("add udp targets: %v", err)
	}

	n.handleSync(websocket.WSMessage{
		Type: "newt/sync",
		Data: SyncData{Targets: TargetsByType{TCP: tcpTargets, UDP: udpTargets}},
	})

	currentTCP, currentUDP := pm.GetTargets()

	wantTCP := map[int]string{8443: "[fd00::10]:443", 8080: "10.0.0.5:80"}
	for port, want := range wantTCP {
		if got, ok := currentTCP[tunnelIP][port]; !ok || got != want {
			t.Errorf("tcp target on port %d after sync = %q (present=%v), want %q", port, got, ok, want)
		}
	}

	wantUDP := map[int]string{5353: "[fd00::53]:53", 5354: "10.0.0.53:53"}
	for port, want := range wantUDP {
		if got, ok := currentUDP[tunnelIP][port]; !ok || got != want {
			t.Errorf("udp target on port %d after sync = %q (present=%v), want %q", port, got, ok, want)
		}
	}
}
