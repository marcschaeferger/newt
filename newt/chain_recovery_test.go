package newt

import (
	"testing"
	"time"
)

// TestDataPlaneRecoveredStopsInFlightChain checks that when the old tunnel
// recovers by itself, the recovery chain that is still sending is stopped and
// its chain ID forgotten, so a late exit-node reply cannot start a register
// chain (and re-arm the supervisor) for a tunnel that already works.
func TestDataPlaneRecoveredStopsInFlightChain(t *testing.T) {
	n := &Newt{}
	stopped := 0
	n.stopFunc = func() { stopped++ }
	n.pendingPingChainId = "recovery-chain"
	n.dataPlaneLost.Store(true)
	n.chain.mu.Lock()
	n.scheduleChainRetryLocked(time.Hour)
	n.chain.mu.Unlock()

	n.dataPlaneRecovered()

	if stopped != 1 {
		t.Errorf("in-flight recovery chain stopped %d times, want 1", stopped)
	}
	if n.stopFunc != nil {
		t.Error("stopFunc still set after recovery")
	}
	if n.pendingPingChainId != "" {
		t.Errorf("pendingPingChainId = %q after recovery, want empty so late replies are stale", n.pendingPingChainId)
	}
	if n.dataPlaneLost.Load() {
		t.Error("dataPlaneLost still set after recovery")
	}
	n.chain.mu.Lock()
	timer := n.chain.timer
	n.chain.mu.Unlock()
	if timer != nil {
		t.Error("retry timer still armed after recovery")
	}
}
