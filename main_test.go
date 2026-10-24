package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func probesWithTotals(totals ...float64) []HopTrace {
	out := make([]HopTrace, len(totals))
	for i, t := range totals {
		out[i] = HopTrace{Target: "https://t.example", TotalMs: t, Healthy: true, StatusCode: 200}
	}
	return out
}

func TestPercentile(t *testing.T) {
	hundred := make([]float64, 100)
	for i := range hundred {
		hundred[i] = float64(i + 1)
	}
	cases := []struct {
		name   string
		in     []float64
		q      float64
		expect float64
	}{
		{"empty", nil, 0.5, 0},
		{"single value", []float64{42}, 0.99, 42},
		{"odd median", []float64{1, 2, 3}, 0.5, 2},
		{"even median interpolates", []float64{10, 20, 30, 40}, 0.5, 25},
		{"q zero is min", []float64{5, 9}, 0, 5},
		{"q one is max", []float64{5, 9}, 1, 9},
		{"p50 of 1..100", hundred, 0.50, 50.5},
		{"p90 of 1..100", hundred, 0.90, 90.1},
		{"p95 of 1..100", hundred, 0.95, 95.05},
		{"p99 of 1..100", hundred, 0.99, 99.01},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := percentile(c.in, c.q)
			if math.Abs(got-c.expect) > 1e-9 {
				t.Fatalf("percentile(q=%v) = %v, want %v", c.q, got, c.expect)
			}
		})
	}
}

func TestComputeReportPercentiles(t *testing.T) {
	// Deliberately unsorted: computeReport must sort a copy for its stats.
	totals := make([]float64, 0, 100)
	for i := 100; i >= 1; i-- {
		totals = append(totals, float64(i))
	}
	probes := probesWithTotals(totals...)
	r := computeReport(probes)

	if r.Count != 100 || r.Healthy != 100 {
		t.Fatalf("count/healthy = %d/%d, want 100/100", r.Count, r.Healthy)
	}
	checks := []struct {
		name      string
		got, want float64
	}{
		{"min", r.MinMs, 1},
		{"p50", r.P50Ms, 50.5},
		{"p90", r.P90Ms, 90.1},
		{"p95", r.P95Ms, 95.05},
		{"p99", r.P99Ms, 99.01},
		{"max", r.MaxMs, 100},
	}
	for _, c := range checks {
		if math.Abs(c.got-c.want) > 1e-9 {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if len(r.TotalsMs) != 100 || r.TotalsMs[0] != 1 || r.TotalsMs[99] != 100 {
		t.Errorf("TotalsMs should be the ascending list of 100 samples")
	}
	if probes[0].TotalMs != 100 {
		t.Errorf("computeReport reordered the caller's probes")
	}
	if !(r.P50Ms <= r.P90Ms && r.P90Ms <= r.P95Ms && r.P95Ms <= r.P99Ms && r.P99Ms <= r.MaxMs) {
		t.Errorf("percentiles are not monotonic: %+v", r)
	}
}

func TestComputeReportSmallSets(t *testing.T) {
	r := computeReport(probesWithTotals(30, 10, 20))
	if !approx(r.P50Ms, 20) || !approx(r.MaxMs, 30) || !approx(r.MinMs, 10) {
		t.Errorf("three samples gave p50=%v min=%v max=%v", r.P50Ms, r.MinMs, r.MaxMs)
	}

	empty := computeReport(nil)
	if empty.Count != 0 || empty.P50Ms != 0 || empty.P99Ms != 0 || empty.MaxMs != 0 {
		t.Errorf("empty input should give a zeroed report, got %+v", empty)
	}
	if _, err := time.Parse(time.RFC3339, empty.GeneratedAt); err != nil {
		t.Errorf("GeneratedAt is not RFC3339: %q", empty.GeneratedAt)
	}
}

func TestComputeReportExcludesTransportErrors(t *testing.T) {
	probes := []HopTrace{
		{Target: "a", TotalMs: 100, Healthy: true, StatusCode: 200},
		{Target: "b", TotalMs: 300, Healthy: false, StatusCode: 503}, // slow but real latency
		{Target: "c", TotalMs: 2, Error: "dial tcp: no such host"},   // must not drag percentiles down
	}
	r := computeReport(probes)
	if r.Count != 3 || r.Healthy != 1 {
		t.Fatalf("count/healthy = %d/%d, want 3/1", r.Count, r.Healthy)
	}
	if len(r.TotalsMs) != 2 {
		t.Fatalf("TotalsMs has %d entries, want 2 (error probe excluded)", len(r.TotalsMs))
	}
	if !approx(r.MinMs, 100) || !approx(r.MaxMs, 300) || !approx(r.P50Ms, 200) {
		t.Errorf("min/p50/max = %v/%v/%v, want 100/200/300", r.MinMs, r.P50Ms, r.MaxMs)
	}
}

func TestTLSVersionName(t *testing.T) {
	cases := []struct {
		in   uint16
		want string
	}{
		{tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS10, "TLS 1.0"},
		{0, "Plain HTTP"},
		{0x0300, "Unknown (0x0300)"},
		{0xfefd, "Unknown (0xfefd)"},
	}
	for _, c := range cases {
		if got := tlsVersionName(c.in); got != c.want {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestWaterfallBar(t *testing.T) {
	if got := waterfallBar(10, 10, 10, 10, 40, 20); got != "░░░░░▒▒▒▒▒▓▓▓▓▓█████" {
		t.Errorf("even phases gave %q", got)
	}
	if got := waterfallBar(0, 0, 0, 20, 40, 10); got != "█████     " {
		t.Errorf("a lone 20ms phase on a 40ms scale should fill half the gauge, got %q", got)
	}
	if got := waterfallBar(5, 5, 5, 5, 0, 8); got != "        " {
		t.Errorf("zero scale should be blank, got %q", got)
	}
	if got := waterfallBar(999, 999, 999, 999, 10, 12); len([]rune(got)) != 12 {
		t.Errorf("overflowing phases must clamp to the gauge width, got %d runes", len([]rune(got)))
	}
	if got := waterfallBar(1, 1, 1, 1, 4, 0); got != "" {
		t.Errorf("zero width should be empty, got %q", got)
	}
}

func sampleReport() FleetReport {
	probes := []HopTrace{
		{Target: "https://hackclub.com", StatusCode: 200, DNSMs: 8.4, TCPConnectMs: 19.2, TLSHandshake: 31.5, ServerWaitMs: 39.1, TotalMs: 100.0, Healthy: true,
			Chain: []CertInfo{{Subject: "hackclub.com"}}, CertDaysLeft: 78},
		{Target: "https://a-very-long-hostname.example.com/path", StatusCode: 200, DNSMs: 4, TCPConnectMs: 4, TLSHandshake: 4, ServerWaitMs: 4, TotalMs: 20, Healthy: true},
		{Target: "http://down.example", TotalMs: 3, Error: "dial tcp: connection refused"},
	}
	return computeReport(probes)
}

func TestFormatASCIIWaterfall(t *testing.T) {
	out := formatASCIIWaterfall(sampleReport())
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	var boxed []string
	for _, l := range lines {
		if strings.ContainsAny(string([]rune(l)[:1]), "┌│├└") {
			boxed = append(boxed, l)
		}
	}
	// top, title, separator, header, separator, 3 rows, bottom
	if len(boxed) != 9 {
		t.Fatalf("expected 9 boxed lines, got %d:\n%s", len(boxed), out)
	}
	want := len([]rune(boxed[0]))
	for i, l := range boxed {
		if got := len([]rune(l)); got != want {
			t.Errorf("boxed line %d is %d runes wide, want %d:\n%s", i, got, want, l)
		}
	}

	for _, frag := range []string{
		"goship pulse v" + version,
		"2/3 healthy",
		"hackclub.com",
		"a-very-long-hostname....", // 24 rune column: 21 runes plus an ellipsis
		"78d",
		"n/a",
		"ERR",
		"bar glyphs",
	} {
		if !strings.Contains(out, frag) {
			t.Errorf("output is missing %q:\n%s", frag, out)
		}
	}
	if strings.Contains(out, "https://") {
		t.Errorf("scheme should be trimmed from targets:\n%s", out)
	}
	if !strings.Contains(out, "100.0") || !strings.Contains(out, "█") {
		t.Errorf("expected numeric total and a drawn bar:\n%s", out)
	}
	// The slowest probe fills 100.0 of 100.0 scale only partially (sum of
	// phases is 98.2), so its bar must end with a block glyph and never overflow.
	for _, l := range boxed[5:8] {
		cells := strings.Split(l, "│")
		bar := cells[len(cells)-2]
		if len([]rune(bar)) != barWidth+2 {
			t.Errorf("bar cell is %d runes, want %d: %q", len([]rune(bar)), barWidth+2, bar)
		}
	}
}

func TestFormatASCIIWaterfallEmpty(t *testing.T) {
	out := formatASCIIWaterfall(computeReport(nil))
	if !strings.Contains(out, "0/0 healthy") {
		t.Errorf("empty report should still render a frame:\n%s", out)
	}
	if strings.Contains(out, "NaN") || strings.Contains(out, "Inf") {
		t.Errorf("empty report leaked NaN or Inf:\n%s", out)
	}
}

func TestMedianPerTarget(t *testing.T) {
	probes := []HopTrace{
		{Target: "a", TotalMs: 30},
		{Target: "b", TotalMs: 5, Error: "boom"},
		{Target: "a", TotalMs: 10},
		{Target: "a", TotalMs: 20},
		{Target: "b", TotalMs: 6, Error: "boom again"},
	}
	got := medianPerTarget(probes)
	if len(got) != 2 || got[0].Target != "a" || got[1].Target != "b" {
		t.Fatalf("expected targets a then b, got %+v", got)
	}
	if got[0].TotalMs != 20 {
		t.Errorf("median of 10,20,30 should be 20, got %v", got[0].TotalMs)
	}
	if got[1].Error != "boom" {
		t.Errorf("all-failed target should surface its first error, got %q", got[1].Error)
	}
}

func TestNormalizeTarget(t *testing.T) {
	good := map[string]string{
		"example.com":             "https://example.com",
		"  http://example.com/x ": "http://example.com/x",
		"localhost:8080":          "https://localhost:8080",
	}
	for in, want := range good {
		got, err := normalizeTarget(in)
		if err != nil || got != want {
			t.Errorf("normalizeTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "   ", "ftp://example.com", "file:///etc/passwd", "https://"} {
		if got, err := normalizeTarget(bad); err == nil {
			t.Errorf("normalizeTarget(%q) = %q, want an error", bad, got)
		}
	}
}

func TestCertInfoFrom(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "bench.example"},
		NotBefore:    now.Add(-24 * time.Hour),
		NotAfter:     now.Add(10*24*time.Hour + 6*time.Hour),
		DNSNames:     []string{"bench.example", "www.bench.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	info := certInfoFrom(cert, now)
	if info.Subject != "bench.example" || info.Issuer != "bench.example" {
		t.Errorf("subject/issuer = %q/%q", info.Subject, info.Issuer)
	}
	if info.DaysLeft != 10 {
		t.Errorf("DaysLeft = %d, want 10", info.DaysLeft)
	}
	if info.KeyAlg != "ECDSA P-256" {
		t.Errorf("KeyAlg = %q, want ECDSA P-256", info.KeyAlg)
	}
	if info.SANCount != 2 || len(info.SANs) != 2 {
		t.Errorf("SAN count = %d (%v)", info.SANCount, info.SANs)
	}
	if len(info.SHA256) != 64 {
		t.Errorf("fingerprint should be 64 hex chars, got %d", len(info.SHA256))
	}

	expired := certInfoFrom(cert, now.Add(30*24*time.Hour))
	if expired.DaysLeft >= 0 {
		t.Errorf("an expired certificate must report negative days, got %d", expired.DaysLeft)
	}
}

func TestProbeEndpointPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(15 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := probeEndpoint(context.Background(), srv.URL, 3*time.Second)
	if p.Error != "" {
		t.Fatalf("unexpected error: %s", p.Error)
	}
	if p.StatusCode != 200 || !p.Healthy {
		t.Errorf("status/healthy = %d/%v", p.StatusCode, p.Healthy)
	}
	if p.TLSVersion != "Plain HTTP" || len(p.Chain) != 0 {
		t.Errorf("plain HTTP should have no TLS data, got %q chain=%d", p.TLSVersion, len(p.Chain))
	}
	if p.ServerWaitMs < 10 {
		t.Errorf("server wait %.2fms should reflect the 15ms handler delay", p.ServerWaitMs)
	}
	if p.TotalMs < p.ServerWaitMs {
		t.Errorf("total %.2f is smaller than server wait %.2f", p.TotalMs, p.ServerWaitMs)
	}
}

func TestProbeEndpointRejectsBadScheme(t *testing.T) {
	p := probeEndpoint(context.Background(), "ftp://example.com", time.Second)
	if p.Error == "" || p.Healthy {
		t.Errorf("ftp target should fail validation, got %+v", p)
	}
}

func TestAPIProbeHandler(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	api := httptest.NewServer(newMux([]string{backend.URL}, 2*time.Second))
	defer api.Close()

	resp, err := http.Get(api.URL + "/api/probe?samples=3&targets=" + url.QueryEscape(backend.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("CORS should not be opened up, got %q", got)
	}
	var body apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Count != 3 || body.SamplesPerTarget != 3 || len(body.TotalsMs) != 3 {
		t.Errorf("expected 3 samples, got count=%d samples=%d totals=%d", body.Count, body.SamplesPerTarget, len(body.TotalsMs))
	}
	if !strings.Contains(body.ASCII, "goship pulse") {
		t.Errorf("ascii field missing: %q", body.ASCII)
	}

	for _, q := range []string{
		"targets=ftp://x.example",
		"samples=0",
		"samples=99",
		"targets=" + strings.Repeat("a.example,", maxTargets+1),
	} {
		r, err := http.Get(api.URL + "/api/probe?" + q)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusBadRequest {
			t.Errorf("query %q gave status %d, want 400", q, r.StatusCode)
		}
	}
}

func TestDashboardServesOnlyIndex(t *testing.T) {
	api := httptest.NewServer(newMux(nil, time.Second))
	defer api.Close()

	r, err := http.Get(api.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 200 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Errorf("/ gave %d %q", r.StatusCode, r.Header.Get("Content-Type"))
	}
	for _, p := range []string{"/.git/config", "/main.go", "/go.mod"} {
		r, err := http.Get(api.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusNotFound {
			t.Errorf("%s should be 404, got %d", p, r.StatusCode)
		}
	}
}
