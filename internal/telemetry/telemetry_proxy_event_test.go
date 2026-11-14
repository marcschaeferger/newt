package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The attribute allowlist view must keep the "event" label on
// newt_proxy_connections_total, otherwise opened and closed are summed.
func TestProxyConnectionEventLabelIsExported(t *testing.T) {
	ctx := context.Background()
	resetMetricsForTest()
	cfg := Config{ServiceName: "newt", PromEnabled: true, AdminAddr: "127.0.0.1:0"}
	tel, err := Init(ctx, cfg)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()

	if tel.PrometheusHandler == nil {
		t.Fatalf("prom handler nil")
	}
	ts := httptest.NewServer(tel.PrometheusHandler)
	defer ts.Close()

	IncProxyConnectionEvent(ctx, "", ProtocolTCP, ProxyConnectionOpened)
	IncProxyConnectionEvent(ctx, "", ProtocolTCP, ProxyConnectionOpened)
	IncProxyConnectionEvent(ctx, "", ProtocolTCP, ProxyConnectionClosed)

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)

	var series []string
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "newt_proxy_connections_total{") {
			series = append(series, line)
		}
	}
	if len(series) == 0 {
		t.Fatalf("newt_proxy_connections_total not exported, got: %s", body)
	}
	want := map[string]string{
		`event="opened"`: " 2",
		`event="closed"`: " 1",
	}
	for label, value := range want {
		found := false
		for _, s := range series {
			if strings.Contains(s, label) {
				found = true
				if !strings.HasSuffix(s, value) {
					t.Errorf("series %q: want value%s", s, value)
				}
			}
		}
		if !found {
			t.Errorf("no newt_proxy_connections_total series with %s; series: %v", label, series)
		}
	}
}
