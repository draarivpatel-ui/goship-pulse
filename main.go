package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dashboardHTML is the single-file web bench. It is embedded so the server
// exposes exactly one static document and never the working directory.
//
//go:embed index.html
var dashboardHTML []byte

const (
	version        = "1.1"
	maxTargets     = 12
	maxSamples     = 10
	barWidth       = 24
	targetColWidth = 24
)

// CertInfo describes one certificate presented by the server.
type CertInfo struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DaysLeft  int      `json:"days_left"`
	SigAlg    string   `json:"sig_alg"`
	KeyAlg    string   `json:"key_alg"`
	IsCA      bool     `json:"is_ca"`
	SANCount  int      `json:"san_count"`
	SANs      []string `json:"sans,omitempty"`
	SHA256    string   `json:"sha256"`
}

// HopTrace records exact phase timings for a single HTTP probe.
type HopTrace struct {
	Target       string     `json:"target"`
	Sample       int        `json:"sample"`
	StatusCode   int        `json:"status_code"`
	Protocol     string     `json:"protocol"`
	RemoteAddr   string     `json:"remote_addr"`
	TotalMs      float64    `json:"total_ms"`
	DNSMs        float64    `json:"dns_ms"`
	TCPConnectMs float64    `json:"tcp_connect_ms"`
	TLSHandshake float64    `json:"tls_handshake_ms"`
	ServerWaitMs float64    `json:"server_wait_ms"`
	TLSVersion   string     `json:"tls_version"`
	CipherSuite  string     `json:"cipher_suite"`
	ALPN         string     `json:"alpn,omitempty"`
	CertDaysLeft int        `json:"cert_days_left"`
	Chain        []CertInfo `json:"chain,omitempty"`
	Healthy      bool       `json:"healthy"`
	Error        string     `json:"error,omitempty"`
}

// FleetReport aggregates multi-endpoint probe telemetry and latency percentiles.
// Percentiles use linear interpolation over the sorted totals of every probe
// that completed without a transport error (a 503 is still a valid latency).
type FleetReport struct {
	GeneratedAt      string     `json:"generated_at"`
	Count            int        `json:"count"`
	Healthy          int        `json:"healthy"`
	SamplesPerTarget int        `json:"samples_per_target"`
	MinMs            float64    `json:"min_ms"`
	P50Ms            float64    `json:"p50_ms"`
	P90Ms            float64    `json:"p90_ms"`
	P95Ms            float64    `json:"p95_ms"`
	P99Ms            float64    `json:"p99_ms"`
	MaxMs            float64    `json:"max_ms"`
	TotalsMs         []float64  `json:"totals_ms"`
	Probes           []HopTrace `json:"probes"`
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
	case 0:
		return "Plain HTTP"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", v)
	}
}

// normalizeTarget turns user input into a probeable http or https URL.
func normalizeTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty target")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid target %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme %q (use http or https)", u.Scheme)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("missing host in %q", raw)
	}
	return u.String(), nil
}

func nameOf(n pkix.Name) string {
	if n.CommonName != "" {
		return n.CommonName
	}
	if len(n.Organization) > 0 {
		return n.Organization[0]
	}
	return n.String()
}

func keyDescription(c *x509.Certificate) string {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + pub.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return c.PublicKeyAlgorithm.String()
	}
}

func certInfoFrom(c *x509.Certificate, now time.Time) CertInfo {
	sum := sha256.Sum256(c.Raw)
	info := CertInfo{
		Subject:   nameOf(c.Subject),
		Issuer:    nameOf(c.Issuer),
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  c.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:  int(math.Floor(c.NotAfter.Sub(now).Hours() / 24)),
		SigAlg:    c.SignatureAlgorithm.String(),
		KeyAlg:    keyDescription(c),
		IsCA:      c.IsCA,
		SANCount:  len(c.DNSNames),
		SHA256:    hex.EncodeToString(sum[:]),
	}
	for i, n := range c.DNSNames {
		if i >= 10 {
			break
		}
		info.SANs = append(info.SANs, n)
	}
	return info
}

func msSince(t time.Time) float64 {
	return float64(time.Since(t).Microseconds()) / 1000.0
}

func probeEndpoint(ctx context.Context, rawURL string, timeout time.Duration) HopTrace {
	res := HopTrace{Target: rawURL}
	norm, err := normalizeTarget(rawURL)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Target = norm

	var dnsStart, connStart, tlsStart, gotConn, firstByte time.Time
	var remoteAddr string
	var tlsState *tls.ConnectionState

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			dnsStart = time.Now()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				res.DNSMs = msSince(dnsStart)
			}
		},
		ConnectStart: func(_, _ string) {
			connStart = time.Now()
		},
		ConnectDone: func(_, addr string, _ error) {
			remoteAddr = addr
			if !connStart.IsZero() {
				res.TCPConnectMs = msSince(connStart)
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
				res.TLSHandshake = msSince(tlsStart)
			}
		},
		GotConn: func(_ httptrace.GotConnInfo) {
			gotConn = time.Now()
		},
		GotFirstResponseByte: func() {
			firstByte = time.Now()
			if !gotConn.IsZero() {
				res.ServerWaitMs = msSince(gotConn)
			}
		},
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(reqCtx, trace), http.MethodGet, norm, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("User-Agent", "GoshipPulse/"+version+" (+https://github.com/draarivpatel-ui/goship-pulse)")

	tr := &http.Transport{
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
		// Report the first response, not wherever a redirect chain ends up.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}

	start := time.Now()
	resp, err := client.Do(req)
	res.TotalMs = msSince(start)
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
		res.ServerWaitMs = msSince(gotConn)
	}

	if tlsState != nil {
		now := time.Now()
		res.TLSVersion = tlsVersionName(tlsState.Version)
		res.CipherSuite = tls.CipherSuiteName(tlsState.CipherSuite)
		res.ALPN = tlsState.NegotiatedProtocol
		for _, c := range tlsState.PeerCertificates {
			res.Chain = append(res.Chain, certInfoFrom(c, now))
		}
		if len(res.Chain) > 0 {
			res.CertDaysLeft = res.Chain[0].DaysLeft
		}
	} else {
		res.TLSVersion = "Plain HTTP"
	}

	return res
}

// percentile returns the q-quantile (0 to 1) of an ascending slice using
// linear interpolation between the two closest ranks.
func percentile(sorted []float64, q float64) float64 {
	n := len(sorted)
	switch {
	case n == 0:
		return 0
	case n == 1 || q <= 0:
		return sorted[0]
	case q >= 1:
		return sorted[n-1]
	}
	rank := q * float64(n-1)
	lo := int(math.Floor(rank))
	hi := lo + 1
	if hi >= n {
		hi = n - 1
	}
	return sorted[lo] + (sorted[hi]-sorted[lo])*(rank-float64(lo))
}

func computeReport(probes []HopTrace) FleetReport {
	totals := make([]float64, 0, len(probes))
	healthy := 0
	for _, p := range probes {
		if p.Healthy {
			healthy++
		}
		if p.Error == "" {
			totals = append(totals, p.TotalMs)
		}
	}
	sort.Float64s(totals)
	r := FleetReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Count:       len(probes),
		Healthy:     healthy,
		TotalsMs:    totals,
		Probes:      probes,
	}
	if len(totals) > 0 {
		r.MinMs = totals[0]
		r.MaxMs = totals[len(totals)-1]
		r.P50Ms = percentile(totals, 0.50)
		r.P90Ms = percentile(totals, 0.90)
		r.P95Ms = percentile(totals, 0.95)
		r.P99Ms = percentile(totals, 0.99)
	}
	return r
}

// medianPerTarget picks one representative probe per target, in first-seen
// order. It is the lower-median successful sample, or the first failure when
// no sample succeeded.
func medianPerTarget(probes []HopTrace) []HopTrace {
	order := []string{}
	groups := map[string][]HopTrace{}
	for _, p := range probes {
		if _, ok := groups[p.Target]; !ok {
			order = append(order, p.Target)
		}
		groups[p.Target] = append(groups[p.Target], p)
	}
	out := make([]HopTrace, 0, len(order))
	for _, t := range order {
		var ok []HopTrace
		for _, p := range groups[t] {
			if p.Error == "" {
				ok = append(ok, p)
			}
		}
		if len(ok) == 0 {
			out = append(out, groups[t][0])
			continue
		}
		sort.SliceStable(ok, func(i, j int) bool { return ok[i].TotalMs < ok[j].TotalMs })
		out = append(out, ok[(len(ok)-1)/2])
	}
	return out
}

func padRight(s string, w int) string {
	n := len([]rune(s))
	if n >= w {
		return string([]rune(s)[:w])
	}
	return s + strings.Repeat(" ", w-n)
}

func shortTarget(t string, w int) string {
	t = strings.TrimPrefix(strings.TrimPrefix(t, "https://"), "http://")
	t = strings.TrimSuffix(t, "/")
	r := []rune(t)
	if len(r) > w {
		return string(r[:w-3]) + "..."
	}
	return t
}

// waterfallBar draws the four phases as proportional glyph runs inside a
// fixed-width gauge. Glyph density differs per phase so it reads without colour.
func waterfallBar(dns, tcp, tlsMs, ttfb, scale float64, width int) string {
	if width <= 0 {
		return ""
	}
	cells := []rune(strings.Repeat(" ", width))
	if scale <= 0 {
		return string(cells)
	}
	glyphs := []rune{'░', '▒', '▓', '█'}
	cum, prev := 0.0, 0
	for i, p := range []float64{dns, tcp, tlsMs, ttfb} {
		if p > 0 {
			cum += p
		}
		end := int(math.Round(cum / scale * float64(width)))
		if end > width {
			end = width
		}
		for j := prev; j < end; j++ {
			cells[j] = glyphs[i]
		}
		if end > prev {
			prev = end
		}
	}
	return string(cells)
}

// formatASCIIWaterfall renders the report as a box-drawn table. Every boxed
// line has the same rune width so the frame stays aligned.
func formatASCIIWaterfall(r FleetReport) string {
	widths := []int{targetColWidth, 4, 7, 7, 7, 7, 7, 6, barWidth}
	inner := len(widths) - 1
	for _, w := range widths {
		inner += w + 2
	}
	border := func(l, m, rt string) string {
		parts := make([]string, len(widths))
		for i, w := range widths {
			parts[i] = strings.Repeat("─", w+2)
		}
		return l + strings.Join(parts, m) + rt
	}
	row := func(cells ...string) string {
		parts := make([]string, len(widths))
		for i, w := range widths {
			parts[i] = " " + padRight(cells[i], w) + " "
		}
		return "│" + strings.Join(parts, "│") + "│"
	}

	reps := medianPerTarget(r.Probes)
	scale := 0.0
	for _, p := range reps {
		if p.TotalMs > scale {
			scale = p.TotalMs
		}
	}

	title := fmt.Sprintf(" goship pulse v%s | %d/%d healthy | n=%d | p50 %.1f | p90 %.1f | p95 %.1f | p99 %.1f | max %.1f ms",
		version, r.Healthy, r.Count, len(r.TotalsMs), r.P50Ms, r.P90Ms, r.P95Ms, r.P99Ms, r.MaxMs)

	var b strings.Builder
	b.WriteString("┌" + strings.Repeat("─", inner) + "┐\n")
	b.WriteString("│" + padRight(title, inner) + "│\n")
	b.WriteString(border("├", "┬", "┤") + "\n")
	b.WriteString(row("target", "code", "dns", "tcp", "tls", "ttfb", "total", "cert", "waterfall") + "\n")
	b.WriteString(border("├", "┼", "┤") + "\n")
	for _, p := range reps {
		cert := "n/a"
		if len(p.Chain) > 0 {
			cert = fmt.Sprintf("%dd", p.CertDaysLeft)
		}
		status := strconv.Itoa(p.StatusCode)
		if p.Error != "" {
			status = "ERR"
		}
		b.WriteString(row(
			shortTarget(p.Target, targetColWidth), status,
			fmt.Sprintf("%.1f", p.DNSMs), fmt.Sprintf("%.1f", p.TCPConnectMs),
			fmt.Sprintf("%.1f", p.TLSHandshake), fmt.Sprintf("%.1f", p.ServerWaitMs),
			fmt.Sprintf("%.1f", p.TotalMs), cert,
			waterfallBar(p.DNSMs, p.TCPConnectMs, p.TLSHandshake, p.ServerWaitMs, scale, barWidth),
		) + "\n")
	}
	b.WriteString(border("└", "┴", "┘") + "\n")
	b.WriteString(fmt.Sprintf("bar glyphs  ░ dns  ▒ tcp  ▓ tls  █ ttfb   full scale %.1f ms\n", scale))
	return b.String()
}

func renderASCIIWaterfall(r FleetReport) {
	fmt.Print(formatASCIIWaterfall(r))
}

func runConcurrentProbes(ctx context.Context, targets []string, samples int, timeout time.Duration) FleetReport {
	if samples < 1 {
		samples = 1
	}
	out := make([][]HopTrace, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(idx int, urlStr string) {
			defer wg.Done()
			// Samples for one endpoint run back to back so they do not
			// compete with each other for the local network stack.
			for s := 0; s < samples; s++ {
				if ctx.Err() != nil {
					return
				}
				p := probeEndpoint(ctx, urlStr, timeout)
				p.Sample = s + 1
				out[idx] = append(out[idx], p)
			}
		}(i, t)
	}
	wg.Wait()
	var flat []HopTrace
	for _, group := range out {
		flat = append(flat, group...)
	}
	report := computeReport(flat)
	report.SamplesPerTarget = samples
	return report
}

type apiResponse struct {
	FleetReport
	ASCII string `json:"ascii"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func newMux(defaultTargets []string, timeout time.Duration) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version, "default_targets": defaultTargets})
	})

	mux.HandleFunc("/api/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET"})
			return
		}
		raw := defaultTargets
		if q := r.URL.Query().Get("targets"); q != "" {
			raw = strings.Split(q, ",")
		}
		var targets []string
		for _, t := range raw {
			if strings.TrimSpace(t) == "" {
				continue
			}
			n, err := normalizeTarget(t)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			targets = append(targets, n)
		}
		if len(targets) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no targets"})
			return
		}
		if len(targets) > maxTargets {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("at most %d targets per run", maxTargets)})
			return
		}
		samples := 1
		if s := r.URL.Query().Get("samples"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 1 || n > maxSamples {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("samples must be 1 to %d", maxSamples)})
				return
			}
			samples = n
		}
		report := runConcurrentProbes(r.Context(), targets, samples, timeout)
		writeJSON(w, http.StatusOK, apiResponse{FleetReport: report, ASCII: formatASCIIWaterfall(report)})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/index.html" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(dashboardHTML)
	})
	return mux
}

func serveDashboard(addr string, defaultTargets []string, timeout time.Duration) error {
	fmt.Printf("Goship Pulse live telemetry server listening on http://%s\n", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           newMux(defaultTargets, timeout),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return srv.ListenAndServe()
}

func main() {
	jsonOut := flag.Bool("json", false, "Emit structured JSON telemetry report")
	serveAddr := flag.String("serve", "", "Run live HTTP telemetry server and web dashboard (e.g. 127.0.0.1:8080)")
	timeoutMs := flag.Int("timeout", 6000, "Per-probe timeout in milliseconds")
	samples := flag.Int("n", 1, fmt.Sprintf("Probes per endpoint, 1 to %d (more samples give a real distribution)", maxSamples))
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
	if *samples < 1 || *samples > maxSamples {
		fmt.Fprintf(os.Stderr, "-n must be between 1 and %d\n", maxSamples)
		os.Exit(2)
	}

	timeout := time.Duration(*timeoutMs) * time.Millisecond
	if *serveAddr != "" {
		if err := serveDashboard(*serveAddr, targets, timeout); err != nil {
			fmt.Fprintln(os.Stderr, "server error:", err)
			os.Exit(1)
		}
		return
	}

	norm := make([]string, 0, len(targets))
	for _, t := range targets {
		n, err := normalizeTarget(t)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		norm = append(norm, n)
	}

	report := runConcurrentProbes(context.Background(), norm, *samples, timeout)
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
		return
	}
	renderASCIIWaterfall(report)
}
