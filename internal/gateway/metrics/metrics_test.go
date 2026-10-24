package metrics

import (
	"bytes"
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := New()
	r.Inc("gateway_requests_total", map[string]string{"op": "PutObject", "status": "200"})
	r.Add("gateway_bytes_total", nil, 4096)
	r.SetGauge("gateway_inflight", map[string]string{"op": "GetObject"}, 3)

	var buf bytes.Buffer
	if err := r.WritePrometheus(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`# TYPE gateway_requests_total counter`,
		`gateway_requests_total{op="PutObject",status="200"} 1`,
		`gateway_bytes_total 4096`,
		`gateway_inflight{op="GetObject"} 3`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("exposition missing %q\n%s", want, out)
		}
	}
}

func TestNilRegistryIsNoop(t *testing.T) {
	var r *Registry
	r.Inc("x", nil)
	r.Add("x", nil, 1)
	r.SetGauge("x", nil, 1)
}
