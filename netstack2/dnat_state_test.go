package netstack2

import (
	"net/netip"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// buildTCPSyn builds a minimal IPv4 TCP SYN packet from src:srcPort to
// dst:dstPort. Checksums are irrelevant here: the tests only exercise
// HandleIncomingPacket's rule matching and NAT bookkeeping.
func buildTCPSyn(t *testing.T, src netip.Addr, srcPort uint16, dst netip.Addr, dstPort uint16) []byte {
	t.Helper()

	totalLen := header.IPv4MinimumSize + header.TCPMinimumSize
	pkt := make([]byte, totalLen)

	ip := header.IPv4(pkt)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(totalLen),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	tcpHdr := header.TCP(pkt[header.IPv4MinimumSize:])
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     1,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})

	return pkt
}

func newTestProxyHandler(t *testing.T) *ProxyHandler {
	t.Helper()

	// Only UDP is enabled so no TCP forwarder goroutine races with the
	// assertions below; the stack simply resets the injected SYNs.
	ph, err := NewProxyHandler(ProxyHandlerOptions{EnableUDP: true, MTU: 1500})
	if err != nil {
		t.Fatalf("NewProxyHandler: %v", err)
	}
	if err := ph.Initialize(noopNotification{}); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(func() { ph.Close() })
	return ph
}

// Once a rule stops rewriting (RewriteTo removed), the handlers must dial the
// original destination again. destRewriteTable used to keep the old DNAT
// target forever, and the handlers prefer it whenever it is present.
func TestHandleIncomingPacket_RuleWithoutRewriteToClearsStaleRewrite(t *testing.T) {
	ph := newTestProxyHandler(t)

	srcAddr := netip.MustParseAddr("10.0.0.5")
	dstAddr := netip.MustParseAddr("10.20.0.5")
	const dstPort = 8080
	srcPrefix := netip.MustParsePrefix("10.0.0.0/24")
	dstPrefix := netip.PrefixFrom(dstAddr, 32)

	ph.ReplaceAllSubnetRules([]SubnetRule{{
		SourcePrefix: srcPrefix,
		DestPrefix:   dstPrefix,
		RewriteTo:    "127.0.0.1/32",
	}})
	if !ph.HandleIncomingPacket(buildTCPSyn(t, srcAddr, 40000, dstAddr, dstPort)) {
		t.Fatal("expected packet to match the DNAT rule")
	}
	if got, ok := ph.LookupDestinationRewrite(srcAddr.String(), dstAddr.String(), dstPort, uint8(header.TCPProtocolNumber)); !ok || got != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("expected rewrite to 127.0.0.1 while the DNAT rule is active, got %v (ok=%t)", got, ok)
	}

	ph.ReplaceAllSubnetRules([]SubnetRule{{
		SourcePrefix: srcPrefix,
		DestPrefix:   dstPrefix,
	}})
	if !ph.HandleIncomingPacket(buildTCPSyn(t, srcAddr, 40001, dstAddr, dstPort)) {
		t.Fatal("expected packet to match the plain rule")
	}

	if got, ok := ph.LookupDestinationRewrite(srcAddr.String(), dstAddr.String(), dstPort, uint8(header.TCPProtocolNumber)); ok {
		t.Errorf("stale rewrite: handler would dial %s:%d instead of %s:%d", got, dstPort, dstAddr, dstPort)
	}
}

// For a non-loopback DNAT target the packet reaches gVisor with its
// destination already rewritten, so the forwarder reports the rewritten
// address as id.LocalAddress and the TCP/UDP handlers release the
// connection with that address. The NAT entries are keyed by the original
// destination and must still be released.
func TestReleaseConnectionState_NonLoopbackRewriteUsesPostDNATTuple(t *testing.T) {
	ph := newTestProxyHandler(t)

	srcAddr := netip.MustParseAddr("10.0.0.5")
	aliasAddr := netip.MustParseAddr("10.20.20.9")
	realAddr := netip.MustParseAddr("192.0.2.10")
	const srcPort, dstPort = 40000, 8080

	ph.AddSubnetRule(SubnetRule{
		SourcePrefix: netip.MustParsePrefix("10.0.0.0/24"),
		DestPrefix:   netip.PrefixFrom(aliasAddr, 32),
		RewriteTo:    realAddr.String() + "/32",
	})
	if !ph.HandleIncomingPacket(buildTCPSyn(t, srcAddr, srcPort, aliasAddr, dstPort)) {
		t.Fatal("expected packet to match the DNAT rule")
	}

	ph.natMu.RLock()
	nat, rev := len(ph.natTable), len(ph.reverseNatTable)
	ph.natMu.RUnlock()
	if nat != 1 || rev != 1 {
		t.Fatalf("expected one NAT entry after the SYN, got natTable=%d reverseNatTable=%d", nat, rev)
	}

	// Same tuple handleTCPConn passes: id.LocalAddress is the rewritten address.
	ph.releaseConnectionState(srcAddr.String(), srcPort, realAddr.String(), dstPort, uint8(header.TCPProtocolNumber))

	ph.natMu.RLock()
	nat, rev = len(ph.natTable), len(ph.reverseNatTable)
	ph.natMu.RUnlock()
	if nat != 0 || rev != 0 {
		t.Errorf("NAT state leaked after the connection closed: natTable=%d reverseNatTable=%d", nat, rev)
	}
}
