# Newt OpenTelemetry Review (combined)

## Overview

Dieses kombinierte Dokument fasst die narrative Review aus `otel-review.md` zusammen
und enthält das komplette Metrik-Inventar aus `temp.md` als Referenz-Appendix. Es
beinhaltet: eine kurze Übersicht, Tracing-Footprint, Guideline-Check, ein vollständiges
Metrik-Inventar, Lücken/Empfehlungen und eine priorisierte Backlog-Liste.

Zielgruppe: Architekt:innen, SREs und Entwickler:innen, die Instrumentation prüfen, priorisieren
oder implementieren wollen.

## Kurz: Aktueller Stand der Instrumentation

- Alle Instrumente werden in `internal/telemetry/metrics.go` registriert und gruppiert
  (site, tunnel, connection, config, build, websocket, proxy).
- Ein globaler Attributfilter begrenzt exponierte Label auf eine erlaubte Liste
  (`site_id`, `region` + kuratierte Dimensions) um Prometheus-Cardinality zu
  begrenzen.
- Tracing ist optional (OTLP) und derzeit begrenzt auf WebSocket-Connect und den
  Admin-HTTP-Handler (`/metrics`, `/healthz`).

## Metric inventory

Die folgende Tabelle listet jedes registrierte Instrument, die Pfade/Helper, die es
emittieren, und ein Beispiel für eine Zeitreihe. Attribute fügen standardmäßig `site_id`
und optional `region` hinzu.

| Metric | Instrument & unit | Purpose | Emission path | Example series |
| --- | --- | --- | --- | --- |
| `newt_site_registrations_total` | Counter | Counts Pangolin registration attempts keyed by result (`success`, `failure`). | `telemetry.IncSiteRegistration` (called after registration completes). | `newt_site_registrations_total{result="success",site_id="abc"} 1` |
| `newt_site_online` | Observable gauge | 0/1 heartbeat for the active site, driven by the registered `StateView`. | `telemetry.SetObservableCallback` via `state.TelemetryView`. | `newt_site_online{site_id="self"} 1` |
| `newt_site_last_heartbeat_seconds` | Observable gauge | Seconds since the last Pangolin heartbeat. | Same callback as above using `state.TelemetryView.TouchHeartbeat`. | `newt_site_last_heartbeat_seconds{site_id="self"} 3.2` |
| `newt_tunnel_sessions` | Observable gauge | Active sessions per tunnel; collapses to site total when `tunnel_id` emission is disabled. | `state.TelemetryView.SessionsByTunnel` via `RegisterStateView`. | `newt_tunnel_sessions{site_id="self",tunnel_id="wgpub"} 2` |
| `newt_tunnel_bytes_total` | Counter (`By`) | Traffic accounting per tunnel, direction (`ingress`/`egress`), protocol (`tcp`/`udp`). | Proxy manager counting writers (`AddTunnelBytes`/`AddTunnelBytesSet`). | `newt_tunnel_bytes_total{direction="egress",protocol="tcp",site_id="self",tunnel_id="wgpub"} 8192` |
| `newt_tunnel_latency_seconds` | Histogram (`s`) | RTT samples from WireGuard stack and health pings per tunnel/transport. | `telemetry.ObserveTunnelLatency` from tunnel health checks. | `newt_tunnel_latency_seconds_bucket{transport="wireguard",le="0.05",tunnel_id="wgpub"} 4` |
| `newt_tunnel_reconnects_total` | Counter | Reconnect attempts bucketed by initiator (`client`/`server`) and reason enums. | `telemetry.IncReconnect` across websocket, WG, and utility flows. | `newt_tunnel_reconnects_total{initiator="client",reason="timeout",tunnel_id="wgpub"} 3` |
| `newt_connection_attempts_total` | Counter | Auth and WebSocket attempt counts by transport (`auth`, `websocket`) and result (`success`/`failure`). | `telemetry.IncConnAttempt` in auth/token and dial paths. | `newt_connection_attempts_total{transport="websocket",result="failure",site_id="self"} 2` |
| `newt_connection_errors_total` | Counter | Connection error tally keyed by transport and canonical error type (`dial_timeout`, `tls_handshake`, `auth_failed`, `io_error`). | `telemetry.IncConnError` in auth/websocket flows. | `newt_connection_errors_total{transport="auth",error_type="auth_failed",site_id="self"} 1` |
| `newt_config_reloads_total` | Counter | Successful/failed config reload attempts. | `telemetry.IncConfigReload` during WireGuard config reloads. | `newt_config_reloads_total{result="success",site_id="self"} 1` |
| `newt_restart_count_total` | Counter | Bumps to 1 at process boot for build info scrapers. | `telemetry.RegisterBuildInfo` called from `Init`. | `newt_restart_count_total{site_id="self"} 1` |
| `newt_config_apply_seconds` | Histogram (`s`) | Measures interface/peer apply duration per phase and result. | `telemetry.ObserveConfigApply` around config updates. | `newt_config_apply_seconds_bucket{phase="peer",result="success",le="0.1"} 5` |
| `newt_cert_rotation_total` | Counter | Certificate rotation events tagged by result. | `telemetry.IncCertRotation` during PKI updates. | `newt_cert_rotation_total{result="success",site_id="self"} 1` |
| `newt_build_info` | Observable gauge | Constant 1 with `version`/`commit` attributes to expose build metadata. | Callback registered in `registerBuildWSProxyInstruments`. | `newt_build_info{version="1.2.3",commit="abc123",site_id="self"} 1` |
| `newt_websocket_connect_latency_seconds` | Histogram (`s`) | Dial latency for Pangolin WebSocket connects annotated with result/error_type. | `telemetry.ObserveWSConnectLatency` inside `Client.establishConnection`. | `newt_websocket_connect_latency_seconds_bucket{result="success",transport="websocket",le="0.5"} 1` |
| `newt_websocket_messages_total` | Counter | Counts inbound/outbound WebSocket messages by direction and logical message type. | `telemetry.IncWSMessage` for ping/pong/text events. | `newt_websocket_messages_total{direction="out",msg_type="ping",site_id="self"} 4` |
| `newt_proxy_active_connections` | Observable gauge | Active TCP/UDP proxy connections per tunnel and protocol. | Proxy manager callback via `SetProxyObservableCallback`. | `newt_proxy_active_connections{protocol="tcp",tunnel_id="wgpub"} 3` |
| `newt_proxy_buffer_bytes` | Observable gauge (`By`) | Size of proxy buffer pools (synchronous path) per tunnel/protocol. | Same proxy callback as above. | `newt_proxy_buffer_bytes{protocol="tcp",tunnel_id="wgpub"} 10240` |
| `newt_proxy_async_backlog_bytes` | Observable gauge (`By`) | Unflushed async byte backlog when deferred accounting is enabled. | Proxy callback when async accounting is turned on. | `newt_proxy_async_backlog_bytes{protocol="udp",tunnel_id="wgpub"} 4096` |
| `newt_proxy_drops_total` | Counter | Proxy write-drop events per protocol/tunnel. | `telemetry.IncProxyDrops` on UDP drop paths. | `newt_proxy_drops_total{protocol="udp",tunnel_id="wgpub"} 2` |

In addition, Go runtime metrics are automatically exported when telemetry is initialised.

## Tracing footprint

- Tracing ist nur aktiv, wenn OTLP-Export konfiguriert ist; `telemetry.Init` wired einen Batch TracerProvider.
- Der Admin HTTP-Server ist mit `otelhttp.NewHandler` gewrappt, damit Admin-Requests Spans erzeugen.
- Der WebSocket-Dial erzeugt einen `ws.connect`-Span. Viele Control- und Data-Pfade sind noch uninstrumentiert.

## Guideline & best-practice alignment

- Naming & units: Instrumente folgen `newt_*` Konventionen; Counters `_total`, Durs `_seconds`.
- Resource attributes: `site_id`, `region` und Build-Metainfos werden gesetzt.
- Attribute hygiene: Ein allow-list View limitiert Label-Keys.
- Runtime metrics & shutdown: Runtime-Instrumentation aktiv; Shutdown draint Exporter.

## Gaps & recommended improvements

Die wichtigsten Lücken (zusammengeführt aus beiden Quellen):

1. Registration failures: `newt_site_registrations_total` muss auch `result="failure"` bei fehlgeschlagenen Registrierungen emittieren.
2. Config reload visibility: Fehlerpfade bei Blueprint-Parsing/-Apply sollten Metriken/Fehlercounter erhöhen.
3. Context propagation: Viele Helpers nutzen `context.Background()` — besser echte Contexts propagieren.
4. Tracing coverage: Blueprint downloads, WireGuard reconfiguration, Docker discovery, Proxy accept/dial sollten Spans erhalten.
5. Proxy telemetry: Mehr Counters für accept/bind errors ergänzen `newt_proxy_drops_total`.
6. Histogram coverage: Bootstrap latency, websocket session duration, ping RTT sollten als Histograms ergänzt werden.
7. Docker discovery metrics: Container add/remove/error counters wenn Discovery aktiviert ist.

## Priorisierte Pre-release Backlog (empfohlen)

1. Bootstrap latency: `newt_site_registration_latency_seconds` (histogram) um Control-plane Latenzen zu messen.
2. Session duration: `newt_websocket_session_duration_seconds` um Verbindungslanglebigkeit zu überwachen.
3. Heartbeat/ping latency: `newt_ping_roundtrip_seconds` für Tunnel-Health SLOs.
4. Proxy accept errors: `newt_proxy_accept_errors_total{protocol,reason}` für Listener-Probleme.
5. Discovery events: `newt_discovery_events_total{action,source}` für Inventar-Churn.

## Concrete implementation notes

- Keep cardinality low: use allow-lists and optional `NEWT_METRICS_INCLUDE_TUNNEL_ID` toggles.
- Use consistent units and buckets (reuse existing latency bucket boundaries).
- Prefer recording failure/success with label `result` to enable simple SLIs/alerts.

## Tracing wishlist

Span targets (to enable end-to-end traces when OTLP aktiv ist):

- Pangolin REST calls (wrap HTTP transport with `otelhttp.NewTransport`).
- Blueprint fetch & apply paths.
- WireGuard handshake / peer apply.
- Docker discovery & registration callbacks.
- Proxy accept/dial loops.

## Next steps / Vorschlag

- Nutze dieses Dokument als Kombination aus Executive Summary und Appendix.
- Vorschlag: `temp.md` als machine-readable CSV/appendix exportieren und diese Datei als primären Review-Text beibehalten.
- Ich kann daraus auf Wunsch eine PR-Checkliste / Issues-Liste erzeugen (Priority + owner).

---
_Quelle:_ Inhalte aus `internal/telemetry` + Review-Notizen (zusammengeführt).
