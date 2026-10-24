package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// HopTrace records exact phase timings for a single HTTP probe.
type HopTrace struct {
	Target       string  `json:"target"`
	StatusCode   int     `json:"status_code"`
	Protocol     string  `json:"protocol"`
	RemoteAddr   string  `json:"remote_addr"`
	TotalMs      float64 `json:"total_ms"`
	DNSMs        float64 `json:"dns_ms"`
	TCPConnectMs float64 `json:"tcp_connect_ms"`
	TLSHandshake float64 `json:"tls_handshake_ms"`
	ServerWaitMs float64 `json:"server_wait_ms"`
	TLSVersion   string  `json:"tls_version"`
	CipherSuite  string  `json:"cipher_suite"`
	CertDaysLeft int     `json:"cert_days_left"`
	Healthy      bool    `json:"healthy"`
	Error        string  `json:"error,omitempty"`
}

// FleetReport aggregates multi-endpoint probe telemetry and latency percentiles.
type FleetReport struct {
	GeneratedAt string     `json:"generated_at"`
	Count       int        `json:"count"`
	Healthy     int        `json:"healthy"`
	P50Ms       float64    `json:"p50_ms"`
	P95Ms       float64    `json:"p95_ms"`
	MaxMs       float64    `json:"max_ms"`
	Probes      []HopTrace `json:"probes"`
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "Plain HTTP"
	}
}

func probeEndpoint(rawURL string, timeout time.Duration) HopTrace {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	res := HopTrace{Target: rawURL}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	var dnsStart, connStart, tlsStart, gotConn, firstByte time.Time
	var remoteAddr string
	var tlsState *tls.ConnectionState

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				res.DNSMs = float64(time.Since(dnsStart).Microseconds()) / 1000.0
			}
		},
		ConnectStart: func(_, _ string) {
			connStart = time.Now()
		},
		ConnectDone: func(_, addr string, err error) {
			remoteAddr = addr
			if !connStart.IsZero() {
				res.TCPConnectMs = float64(time.Since(connStart).Microseconds()) / 1000.0
			}
		},
		TLSHandshakeStart: func() {
			tlsStart = time.Now()
		},
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			if err == nil {
				tlsState = &cs
			}
			if !tlsStart.IsZero() {
				res.TLSHandshake = float64(time.Since(tlsStart).Microseconds()) / 1000.0
			}
		},
		GotConn: func(_ httptrace.GotConnInfo) {
			gotConn = time.Now()
		},
		GotFirstResponseByte: func() {
			firstByte = time.Now()
			if !gotConn.IsZero() {
				res.ServerWaitMs = float64(time.Since(gotConn).Microseconds()) / 1000.0
			}
		},
	}

	req, err := http.NewRequest("GET", parsed.String(), nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "GoshipPulse/1.0 (+https://github.com/draarivpatel-ui/goship-pulse)")
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	tr := &http.Transport{
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	start := time.Now()
	resp, err := client.Do(req)
	total := float64(time.Since(start).Microseconds()) / 1000.0
	res.TotalMs = total
	res.RemoteAddr = remoteAddr

	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	res.StatusCode = resp.StatusCode
	res.Protocol = resp.Proto
	res.Healthy = resp.StatusCode >= 200 && resp.StatusCode < 400
	if firstByte.IsZero() && !gotConn.IsZero() {
		res.ServerWaitMs = float64(time.Since(gotConn).Microseconds()) / 1000.0
	}

	if tlsState != nil {
		res.TLSVersion = tlsVersionName(tlsState.Version)
		res.CipherSuite = tls.CipherSuiteName(tlsState.CipherSuite)
		if len(tlsState.PeerCertificates) > 0 {
			expiry := tlsState.PeerCertificates[0].NotAfter
			res.CertDaysLeft = int(time.Until(expiry).Hours() / 24)
		}
	} else {
		res.TLSVersion = "Plain HTTP"
	}

	return res
}

func computeReport(probes []HopTrace) FleetReport {
	var totals []float64
	healthy := 0
	for _, p := range probes {
		totals = append(totals, p.TotalMs)
		if p.Healthy {
			healthy++
		}
	}
	sort.Float64s(totals)
	var p50, p95, maxVal float64
	if len(totals) > 0 {
		p50 = totals[len(totals)/2]
		idx95 := int(float64(len(totals)-1) * 0.95)
		p95 = totals[idx95]
		maxVal = totals[len(totals)-1]
	}
	return FleetReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Count:       len(probes),
		Healthy:     healthy,
		P50Ms:       p50,
		P95Ms:       p95,
		MaxMs:       maxVal,
		Probes:      probes,
	}
}

func renderASCIIWaterfall(r FleetReport) {
	fmt.Println("┌────────────────────────────────────────────────────────────────────────────────────────┐")
	fmt.Printf("│ GOSHIP PULSE v1.0  |  Endpoints %d/%d Healthy  |  p50 %.1fms  |  p95 %.1fms  |  max %.1fms │\n",
		r.Healthy, r.Count, r.P50Ms, r.P95Ms, r.MaxMs)
	fmt.Println("├──────────────────────────┬──────┬─────────┬────────┬────────┬────────┬────────┬────────┤")
	fmt.Println("│ TARGET                   │ CODE │ DNS(ms) │ TCP(ms)│ TLS(ms)│ TTFB   │ TOTAL  │ CERT   │")
	fmt.Println("├──────────────────────────┼──────┼─────────┼────────┼────────┼────────┼────────┼────────┤")
	for _, p := range r.Probes {
		target := strings.TrimPrefix(strings.TrimPrefix(p.Target, "https://"), "http://")
		if len(target) > 24 {
			target = target[:21] + "..."
		}
		certStr := "n/a"
		if p.CertDaysLeft > 0 {
			certStr = fmt.Sprintf("%dd", p.CertDaysLeft)
		}
		status := fmt.Sprintf("%d", p.StatusCode)
		if p.Error != "" {
			status = "ERR"
		}
		fmt.Printf("│ %-24s │ %-4s │ %7.1f │ %6.1f │ %6.1f │ %6.1f │ %6.1f │ %-6s │\n",
			target, status, p.DNSMs, p.TCPConnectMs, p.TLSHandshake, p.ServerWaitMs, p.TotalMs, certStr)
	}
	fmt.Println("└──────────────────────────┴──────┴─────────┴────────┴────────┴────────┴────────┴────────┘")
}

func runConcurrentProbes(targets []string, timeout time.Duration) FleetReport {
	out := make([]HopTrace, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(idx int, urlStr string) {
			defer wg.Done()
			out[idx] = probeEndpoint(urlStr, timeout)
		}(i, t)
	}
	wg.Wait()
	return computeReport(out)
}

func serveDashboard(addr string, defaultTargets []string, timeout time.Duration) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/probe", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		q := r.URL.Query().Get("targets")
		targets := defaultTargets
		if q != "" {
			targets = strings.Split(q, ",")
		}
		report := runConcurrentProbes(targets, timeout)
		_ = json.NewEncoder(w).Encode(report)
	})
	mux.Handle("/", http.FileServer(http.Dir(".")))
	fmt.Printf("Goship Pulse live telemetry server listening on http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

func main() {
	jsonOut := flag.Bool("json", false, "Emit structured JSON telemetry report")
	serveAddr := flag.String("serve", "", "Run live HTTP telemetry server and web dashboard (e.g. 127.0.0.1:8080)")
	timeoutMs := flag.Int("timeout", 6000, "Per-probe timeout in milliseconds")
	flag.Parse()

	targets := flag.Args()
	if len(targets) == 0 {
		targets = []string{
			"https://hackclub.com",
			"https://github.com",
			"https://cloudflare.com",
			"https://pkg.go.dev",
		}
	}

	timeout := time.Duration(*timeoutMs) * time.Millisecond
	if *serveAddr != "" {
		if err := serveDashboard(*serveAddr, targets, timeout); err != nil {
			fmt.Fprintln(os.Stderr, "server error:", err)
			os.Exit(1)
		}
		return
	}

	report := runConcurrentProbes(targets, timeout)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	}
	renderASCIIWaterfall(report)
}
