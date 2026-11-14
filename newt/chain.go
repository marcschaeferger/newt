package newt

import (
	"math/rand"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
)

const (
	defaultPingRequestInterval = 3 * time.Second
	defaultRegisterInterval    = 2 * time.Second
	defaultChainRetryBase      = 5 * time.Second
	defaultChainRetryMax       = 60 * time.Second

	// sendIntervalAttempts mirrors the attempt budget of
	// websocket.Client.SendMessageInterval, after which a chain silently ends.
	sendIntervalAttempts = 16
)

// chainTiming holds the intervals of the ping-request/register chain. Zero
// values select the defaults; tests shorten them.
type chainTiming struct {
	pingRequestInterval time.Duration
	registerInterval    time.Duration
	retryBase           time.Duration
	retryMax            time.Duration
}

// chainSupervisor restarts the newt/ping/request -> newt/wg/register chain
// when it ends without a newt/wg/connect: an empty exit-node list, an
// exhausted SendMessageInterval budget or a failed connect. The retry is
// armed whenever a chain starts and disarmed when a tunnel comes up, on
// newt/wg/terminate and on shutdown.
type chainSupervisor struct {
	mu     sync.Mutex
	timer  *time.Timer
	gen    uint64
	delay  time.Duration
	closed bool
}

func durationOr(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// nextChainBackoffLocked returns the current backoff with jitter in [d/2, d]
// so that sites cut off by the same server restart do not retry in lockstep,
// and doubles the backoff up to the cap. Caller holds n.chain.mu.
func (n *Newt) nextChainBackoffLocked() time.Duration {
	base := durationOr(n.chainTiming.retryBase, defaultChainRetryBase)
	limit := durationOr(n.chainTiming.retryMax, defaultChainRetryMax)
	d := n.chain.delay
	if d < base {
		d = base
	}
	if d > limit {
		d = limit
	}
	n.chain.delay = min(d*2, limit)
	half := d / 2
	return half + time.Duration(rand.Int63n(int64(d-half)+1))
}

// scheduleChainRetryLocked (re)arms the supervisor to start a new ping-request
// chain after delay. Caller holds n.chain.mu.
func (n *Newt) scheduleChainRetryLocked(delay time.Duration) {
	if n.chain.timer != nil {
		n.chain.timer.Stop()
		n.chain.timer = nil
	}
	n.chain.gen++
	if n.chain.closed {
		return
	}
	gen := n.chain.gen
	n.chain.timer = time.AfterFunc(delay, func() { n.retryChain(gen) })
}

// disarmChainRetryLocked cancels a pending retry. Caller holds n.chain.mu.
func (n *Newt) disarmChainRetryLocked() {
	if n.chain.timer != nil {
		n.chain.timer.Stop()
		n.chain.timer = nil
	}
	n.chain.gen++
}

func (n *Newt) retryChain(gen uint64) {
	n.chain.mu.Lock()
	defer n.chain.mu.Unlock()
	if n.chain.closed || gen != n.chain.gen {
		return
	}
	n.chain.timer = nil
	logger.Info("Registration did not complete, requesting exit nodes again")
	n.startPingRequestChainLocked(map[string]interface{}{
		"noCloud": n.config.NoCloud,
	})
}

// startPingRequestChainLocked replaces the running chain with a new
// newt/ping/request interval and arms the supervisor for when its attempts
// run out. Caller holds n.chain.mu.
func (n *Newt) startPingRequestChainLocked(data map[string]interface{}) {
	if n.stopFunc != nil {
		n.stopFunc()
		n.stopFunc = nil
	}
	interval := durationOr(n.chainTiming.pingRequestInterval, defaultPingRequestInterval)
	pingChainId := generateChainId()
	n.pendingPingChainId = pingChainId
	data["chainId"] = pingChainId
	n.stopFunc = n.client.SendMessageInterval("newt/ping/request", data, interval)
	n.scheduleChainRetryLocked(sendIntervalAttempts*interval + n.nextChainBackoffLocked())
}

// startRegisterChainLocked starts the newt/wg/register interval and arms the
// supervisor for when its attempts run out. Caller holds n.chain.mu.
func (n *Newt) startRegisterChainLocked(data map[string]interface{}) {
	interval := durationOr(n.chainTiming.registerInterval, defaultRegisterInterval)
	chainId := generateChainId()
	n.pendingRegisterChainId = chainId
	data["chainId"] = chainId
	n.stopFunc = n.client.SendMessageInterval(topicWGRegister, data, interval)
	n.scheduleChainRetryLocked(sendIntervalAttempts*interval + n.nextChainBackoffLocked())
}

// chainSucceeded disarms the supervisor and resets its backoff once a tunnel
// is up.
func (n *Newt) chainSucceeded() {
	n.chain.mu.Lock()
	defer n.chain.mu.Unlock()
	n.disarmChainRetryLocked()
	n.chain.delay = 0
	n.dataPlaneLost.Store(false)
}

// dataPlaneRecovered is called when the old tunnel answers pings again after
// recovery started. It stops the in-flight recovery chain and forgets its
// chain ID, so a late exit-node reply is discarded as stale and cannot re-arm
// the supervisor or replace the working tunnel.
func (n *Newt) dataPlaneRecovered() {
	n.chain.mu.Lock()
	defer n.chain.mu.Unlock()
	n.dataPlaneLost.Store(false)
	if n.stopFunc != nil {
		n.stopFunc()
		n.stopFunc = nil
	}
	n.pendingPingChainId = ""
	n.disarmChainRetryLocked()
}

// stopChainSupervisor cancels any pending retry for good (shutdown).
func (n *Newt) stopChainSupervisor() {
	n.chain.mu.Lock()
	defer n.chain.mu.Unlock()
	n.chain.closed = true
	n.disarmChainRetryLocked()
}
