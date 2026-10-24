package transport

import (
	"time"

	"github.com/fass-storage/fass/internal/contract"
)

const (
	// maxBatchIDs caps /v1/shards:has batches.
	maxBatchIDs = 10000
	// maxJSONBody caps JSON request bodies on the agent surface.
	maxJSONBody = 1 << 20
)

type putShardResponse struct {
	Checksum uint64 `json:"checksum"`
	Stored   int64  `json:"stored"`
}

type hasRequest struct {
	IDs []string `json:"ids"`
}

type hasResponse struct {
	Present []bool `json:"present"`
}

type inventoryResponse struct {
	Entries []contract.ShardInfo `json:"entries"`
	Next    string               `json:"next"`
}

// tlsStatsResponse is the security block of /v1/stats.
type tlsStatsResponse struct {
	Enabled    bool       `json:"enabled"`
	Mutual     bool       `json:"mutual"`
	Insecure   bool       `json:"insecure"`
	NotAfter   *time.Time `json:"not_after,omitempty"`
	RenewalDue bool       `json:"renewal_due"`
	Issuer     string     `json:"issuer,omitempty"`
	Subject    string     `json:"subject,omitempty"`
}

func tlsStatsFrom(sec SecurityInfo) tlsStatsResponse {
	out := tlsStatsResponse{
		Enabled:    sec.Enabled,
		Mutual:     sec.Mutual,
		Insecure:   sec.Insecure,
		RenewalDue: sec.RenewalDue,
		Issuer:     sec.Issuer,
		Subject:    sec.Subject,
	}
	if sec.Enabled && !sec.NotAfter.IsZero() {
		notAfter := sec.NotAfter.UTC()
		out.NotAfter = &notAfter
	}
	return out
}

type statsResponse struct {
	FreeBytes     int64            `json:"free_bytes"`
	UsedBytes     int64            `json:"used_bytes"`
	TotalBytes    int64            `json:"total_bytes"`
	ReservedBytes int64            `json:"reserved_bytes"`
	ShardCount    int64            `json:"shard_count"`
	SetCount      int64            `json:"set_count"`
	LoadEWMA      float64          `json:"load_ewma"`
	DiskID        string           `json:"disk_id"`
	NodeID        string           `json:"node_id"`
	Version       string           `json:"version"`
	ScrubCursor   string           `json:"scrub_cursor"`
	TLS           tlsStatsResponse `json:"tls"`
}

type healthResponse struct {
	State  string `json:"state"`
	DiskID string `json:"disk_id"`
	NodeID string `json:"node_id"`
	// TLS/insecure are the exact fields an operator checks to spot an
	// accidentally plaintext deployment: {"tls":false,"insecure":true}.
	TLS         bool       `json:"tls"`
	Insecure    bool       `json:"insecure"`
	TLSNotAfter *time.Time `json:"tls_not_after,omitempty"`
}

type scrubResponse struct {
	State string `json:"state"`
}

type errorEnvelope struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// healthState values documented in docs/07 §2.
const (
	stateReady = "ready"
)
