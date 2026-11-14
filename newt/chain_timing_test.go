package newt

import "time"

// setChainTiming shortens the ping-request/register chain intervals so the
// supervisor tests run in a few seconds.
func setChainTiming(n *Newt, pingRequest, register, retryBase, retryMax time.Duration) {
	n.chainTiming = chainTiming{
		pingRequestInterval: pingRequest,
		registerInterval:    register,
		retryBase:           retryBase,
		retryMax:            retryMax,
	}
}
