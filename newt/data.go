package newt

import (
	"encoding/json"
	"fmt"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/websocket"
)

func (n *Newt) handleSync(msg websocket.WSMessage) {
	logger.Info("Received sync message")

	// if there is no wgData or pm, we can't sync targets
	if n.wgData.TunnelIP == "" || n.pm == nil {
		logger.Info(msgNoTunnelOrProxy)
		return
	}

	var syncData SyncData
	jsonData, err := json.Marshal(msg.Data)
	if err != nil {
		logger.Error("Error marshaling sync data: %v", err)
		return
	}

	if err := json.Unmarshal(jsonData, &syncData); err != nil {
		logger.Error("Error unmarshaling sync data: %v", err)
		return
	}

	logger.Debug("Sync data received: TCP targets=%d, UDP targets=%d, health check targets=%d",
		len(syncData.Targets.TCP), len(syncData.Targets.UDP), len(syncData.HealthCheckTargets))

	// Build sets of desired targets (port -> target string)
	desiredTCP := make(map[int]string)
	for _, t := range syncData.Targets.TCP {
		port, target, err := parseTargetString(t)
		if err != nil {
			logger.Warn("Invalid TCP target format: %s (%v)", t, err)
			continue
		}
		desiredTCP[port] = target
	}

	desiredUDP := make(map[int]string)
	for _, t := range syncData.Targets.UDP {
		port, target, err := parseTargetString(t)
		if err != nil {
			logger.Warn("Invalid UDP target format: %s (%v)", t, err)
			continue
		}
		desiredUDP[port] = target
	}

	// Get current targets from proxy manager
	currentTCP, currentUDP := n.pm.GetTargets()

	// Sync TCP targets
	// Remove TCP targets not in desired set
	if tcpForIP, ok := currentTCP[n.wgData.TunnelIP]; ok {
		for port := range tcpForIP {
			if _, exists := desiredTCP[port]; !exists {
				logger.Info("Sync: removing TCP target on port %d", port)
				targetStr := fmt.Sprintf("%d:%s", port, tcpForIP[port])
				n.updateTargets(n.pm, "remove", n.wgData.TunnelIP, "tcp", TargetData{Targets: []string{targetStr}})
			}
		}
	}

	// Add TCP targets that are missing
	for port, target := range desiredTCP {
		needsAdd := true
		if tcpForIP, ok := currentTCP[n.wgData.TunnelIP]; ok {
			if currentTarget, exists := tcpForIP[port]; exists {
				// Check if target address changed
				if currentTarget == target {
					needsAdd = false
				} else {
					// Target changed, remove old one first
					logger.Info("Sync: updating TCP target on port %d", port)
					targetStr := fmt.Sprintf("%d:%s", port, currentTarget)
					n.updateTargets(n.pm, "remove", n.wgData.TunnelIP, "tcp", TargetData{Targets: []string{targetStr}})
				}
			}
		}
		if needsAdd {
			logger.Info("Sync: adding TCP target on port %d -> %s", port, target)
			targetStr := fmt.Sprintf("%d:%s", port, target)
			n.updateTargets(n.pm, "add", n.wgData.TunnelIP, "tcp", TargetData{Targets: []string{targetStr}})
		}
	}

	// Sync UDP targets
	// Remove UDP targets not in desired set
	if udpForIP, ok := currentUDP[n.wgData.TunnelIP]; ok {
		for port := range udpForIP {
			if _, exists := desiredUDP[port]; !exists {
				logger.Info("Sync: removing UDP target on port %d", port)
				targetStr := fmt.Sprintf("%d:%s", port, udpForIP[port])
				n.updateTargets(n.pm, "remove", n.wgData.TunnelIP, "udp", TargetData{Targets: []string{targetStr}})
			}
		}
	}

	// Add UDP targets that are missing
	for port, target := range desiredUDP {
		needsAdd := true
		if udpForIP, ok := currentUDP[n.wgData.TunnelIP]; ok {
			if currentTarget, exists := udpForIP[port]; exists {
				// Check if target address changed
				if currentTarget == target {
					needsAdd = false
				} else {
					// Target changed, remove old one first
					logger.Info("Sync: updating UDP target on port %d", port)
					targetStr := fmt.Sprintf("%d:%s", port, currentTarget)
					n.updateTargets(n.pm, "remove", n.wgData.TunnelIP, "udp", TargetData{Targets: []string{targetStr}})
				}
			}
		}
		if needsAdd {
			logger.Info("Sync: adding UDP target on port %d -> %s", port, target)
			targetStr := fmt.Sprintf("%d:%s", port, target)
			n.updateTargets(n.pm, "add", n.wgData.TunnelIP, "udp", TargetData{Targets: []string{targetStr}})
		}
	}

	// Sync remote exit node subnets
	if n.dev != nil {
		n.updateRemoteExitNodeSubnets(syncData.RemoteExitNodeSubnets)
	}

	// Sync clients WireGuard peers and targets, if clients are set up
	if n.wgService != nil {
		n.wgService.SetCerts(syncData.Certs)
		n.wgService.Sync(syncData.Peers, syncData.ClientTargets, syncData.ClientIdentities)
	}

	// Sync browser gateway targets
	n.syncBrowserGatewayTargets(syncData.BrowserGatewayTargets)

	// Sync health check targets
	if err := n.healthMonitor.SyncTargets(syncData.HealthCheckTargets); err != nil {
		logger.Error("Failed to sync health check targets: %v", err)
	} else {
		logger.Info("Successfully synced health check targets")
	}

	logger.Info("Sync complete")
}
