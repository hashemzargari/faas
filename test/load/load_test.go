//go:build load

package load

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fass-storage/fass/pkg/sdk"
)

const (
	mixedBucket   = "load-mixed"
	churnBucket   = "load-churn"
	verifySamples = 200
)

// latSummary is one operation type's client-side view.
type latSummary struct {
	N         int64   `json:"n"`
	Errors    int64   `json:"errors"`
	Err503    int64   `json:"err_503_retryable"`
	Err5xx    int64   `json:"err_5xx_non_retryable"`
	Err4xx    int64   `json:"err_4xx"`
	NetErrs   int64   `json:"err_network"`
	Bytes     int64   `json:"bytes"`
	P50ms     float64 `json:"p50_ms"`
	P95ms     float64 `json:"p95_ms"`
	P99ms     float64 `json:"p99_ms"`
	Maxms     float64 `json:"max_ms"`
	OpsPerSec float64 `json:"ops_per_sec"`
	MiBPerSec float64 `json:"mib_per_sec"`
}

type meter struct {
	mu      sync.Mutex
	lat     map[string][]time.Duration
	stats   map[string]*latSummary
	raw     []float64 // all client latencies (ms), for the report percentiles
	phase   map[string]string
	windows map[string][2]time.Time
}

func newMeter() *meter {
	return &meter{lat: map[string][]time.Duration{}, stats: map[string]*latSummary{}, phase: map[string]string{}, windows: map[string][2]time.Time{}}
}

func (m *meter) record(kind string, d time.Duration, nbytes int64, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.stats[kind]
	if st == nil {
		st = &latSummary{}
		m.stats[kind] = st
	}
	st.N++
	st.Bytes += nbytes
	m.lat[kind] = append(m.lat[kind], d)
	if err != nil {
		st.Errors++
		var se *sdk.Error
		switch {
		case errors.As(err, &se):
			switch {
			case se.StatusCode == http.StatusServiceUnavailable:
				st.Err503++
			case se.StatusCode >= 500:
				st.Err5xx++
			case se.StatusCode >= 400:
				st.Err4xx++
			default:
				st.NetErrs++
			}
		default:
			st.NetErrs++
		}
	}
}

// reset drops warmup samples so percentiles describe the measured window only.
func (m *meter) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lat = map[string][]time.Duration{}
	m.stats = map[string]*latSummary{}
	m.windows = map[string][2]time.Time{}
}

func (m *meter) setWindow(kind string, start, end time.Time) {
	m.mu.Lock()
	m.windows[kind] = [2]time.Time{start, end}
	m.mu.Unlock()
}

func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func (m *meter) summaries() map[string]latSummary {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]latSummary{}
	for kind, st := range m.stats {
		cp := *st
		vals := make([]float64, 0, len(m.lat[kind]))
		for _, d := range m.lat[kind] {
			vals = append(vals, float64(d.Microseconds())/1000.0)
		}
		sort.Float64s(vals)
		cp.P50ms = pct(vals, 0.50)
		cp.P95ms = pct(vals, 0.95)
		cp.P99ms = pct(vals, 0.99)
		if len(vals) > 0 {
			cp.Maxms = vals[len(vals)-1]
		}
		if w, ok := m.windows[kind]; ok {
			secs := w[1].Sub(w[0]).Seconds()
			if secs > 0 {
				cp.OpsPerSec = float64(cp.N) / secs
				cp.MiBPerSec = float64(cp.Bytes) / (1024 * 1024) / secs
			}
		}
		out[kind] = cp
	}
	return out
}

// expectedContent returns deterministic bytes for a key/sequence and their hash.
func expectedContent(key string, seq int) ([]byte, string) {
	buf := bytes.Repeat([]byte(fmt.Sprintf("%s:%d:", key, seq)), 1)
	size := 4 << 10
	if seq%10 == 0 {
		size = 1 << 20
	}
	if seq%97 == 0 {
		size = 12 << 20 // occasional large object (single PUT; multipart is covered by test/compat)
	}
	raw := make([]byte, size)
	for i := range raw {
		raw[i] = buf[i%len(buf)]
	}
	sum := sha256.Sum256(raw)
	return raw, hex.EncodeToString(sum[:])
}

type verifier struct {
	mu sync.Mutex
	m  map[string]string // key -> sha256 of last written content
}

func (v *verifier) put(key, hash string) {
	v.mu.Lock()
	v.m[key] = hash
	v.mu.Unlock()
}

func (v *verifier) sample(limit int) map[string]string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := map[string]string{}
	n := 0
	for k, h := range v.m {
		out[k] = h
		n++
		if n >= limit {
			break
		}
	}
	return out
}

type phaseWindow struct {
	start, end time.Time
}

func TestMixedWorkloadLoad(t *testing.T) {
	s := &stack{t: t, bin: binDir, dir: filepath.Join(os.TempDir(), "fass-load-work"), logDir: filepath.Join(os.TempDir(), "fass-load-logs")}
	if err := os.MkdirAll(s.logDir, 0o755); err != nil {
		t.Fatalf("log dir: %v", err)
	}
	t.Cleanup(s.shutdown)
	if err := boot(s); err != nil {
		s.dumpOnFailure(err)
		t.Fatalf("boot: %v", err)
	}
	defer s.shutdown()

	// Startup baseline / memory.
	baseMem := s.memAtBoot
	ctx := context.Background()
	s.createBucket(mixedBucket)
	s.createBucket(churnBucket)
	s.setVersioning(churnBucket)

	// Warmup: create the verification/read corpus and let caches/JIT settle.
	ver := &verifier{m: map[string]string{}}
	seed := int64(42)
	for i := 0; i < 300; i++ {
		key := fmt.Sprintf("mixed/hot/%03d", i)
		raw, hash := expectedContent(key, int(seed)+i)
		if _, err := s.clients[0].PutObject(ctx, mixedBucket, key, bytes.NewReader(raw), int64(len(raw)), "application/octet-stream"); err != nil {
			t.Fatalf("warmup put %s: %v", key, err)
		}
		ver.put(key, hash)
	}

	pgBase := s.pgSnapshot(t)
	metricsBefore := s.coordMetricsText()

	// Continuous 1 s Postgres/memory sampler for the whole run (required by the
	// task: activity/lock waiters/dead tuples must be attributable, not a single
	// post-hoc guess).
	var sampleMu sync.Mutex
	pgPeak := pgBase
	minMem := memAvailableMB()
	samplerStop := make(chan struct{})
	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-samplerStop:
				return
			case <-tick.C:
				snap := s.pgSnapshotNoFail()
				mem := memAvailableMB()
				sampleMu.Lock()
				if snap.Active > pgPeak.Active {
					pgPeak.Active = snap.Active
				}
				if snap.LockWaiters > pgPeak.LockWaiters {
					pgPeak.LockWaiters = snap.LockWaiters
				}
				if snap.Connections > pgPeak.Connections {
					pgPeak.Connections = snap.Connections
				}
				if snap.DeadTuples > pgPeak.DeadTuples {
					pgPeak.DeadTuples = snap.DeadTuples
				}
				if mem < minMem {
					minMem = mem
				}
				sampleMu.Unlock()
			}
		}
	}()

	m := newMeter()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	run := func(fn func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctx)
		}()
	}
	client := func(i int) *sdk.Client { return s.clients[i%len(s.clients)] }

	// 32 PUT workers.
	for i := 0; i < 32; i++ {
		i := i
		run(func(c context.Context) {
			seq := i * 100000
			for {
				select {
				case <-stop:
					return
				default:
				}
				seq++
				key := fmt.Sprintf("mixed/put/%02d/%06d", i, seq)
				raw, hash := expectedContent(key, seq)
				start := time.Now()
				_, err := client(i).PutObject(c, mixedBucket, key, bytes.NewReader(raw), int64(len(raw)), "application/octet-stream")
				m.record("put", time.Since(start), int64(len(raw)), err)
				if err == nil {
					ver.put(key, hash)
				}
			}
		})
	}
	// 16 GET workers: hot corpus + recently written keys.
	for i := 0; i < 16; i++ {
		i := i
		run(func(c context.Context) {
			rng := rand.New(rand.NewSource(int64(1000 + i)))
			for {
				select {
				case <-stop:
					return
				default:
				}
				key := fmt.Sprintf("mixed/hot/%03d", rng.Intn(300))
				start := time.Now()
				body, err := client(i).GetObject(c, mixedBucket, key)
				var n int64
				if err == nil {
					raw, rerr := io.ReadAll(body)
					body.Close()
					n = int64(len(raw))
					if rerr != nil {
						err = rerr
					}
				}
				m.record("get", time.Since(start), n, err)
			}
		})
	}
	// 8 List workers (6 through gateways, 2 through the version-listing API).
	for i := 0; i < 8; i++ {
		i := i
		run(func(c context.Context) {
			for {
				select {
				case <-stop:
					return
				default:
				}
				start := time.Now()
				if i < 6 {
					_, _, _, err := client(i).ListObjectsV2Page(c, mixedBucket, "mixed/", "", 100)
					if err == nil {
						// second page via continuation token (bounded)
						_, token, truncated, err2 := client(i).ListObjectsV2Page(c, mixedBucket, "mixed/", "", 50)
						if err2 == nil && truncated && token != "" {
							_, _, _, err = client(i).ListObjectsV2Page(c, mixedBucket, "mixed/", token, 50)
						}
					}
					m.record("list", time.Since(start), 0, err)
				} else {
					// Version listing goes through the coordinator control-plane API
					// (pkg/sdk has no ListObjectVersions); labelled separately.
					code, body := s.coordJSONGET("/v1/objects?bucket=" + churnBucket + "&versions=true&max_keys=50")
					var err error
					if code != http.StatusOK {
						err = fmt.Errorf("vlist status %d: %s", code, body)
					}
					m.record("vlist", time.Since(start), 0, err)
				}
			}
		})
	}
	// 4 version-churn workers: create versions and delete markers (tombstones).
	for i := 0; i < 4; i++ {
		i := i
		run(func(c context.Context) {
			seq := i * 100000
			for {
				select {
				case <-stop:
					return
				default:
				}
				seq++
				key := fmt.Sprintf("churn/%02d/%06d", i, seq)
				raw := []byte(fmt.Sprintf("churn-%s-%d", key, seq))
				start := time.Now()
				_, err := client(i).PutObject(c, churnBucket, key, bytes.NewReader(raw), int64(len(raw)), "text/plain")
				m.record("churn", time.Since(start), int64(len(raw)), err)
				if err == nil {
					start = time.Now()
					err = client(i).DeleteObject(c, churnBucket, key)
					m.record("churn", time.Since(start), 0, err)
				}
			}
		})
	}

	time.Sleep(20 * time.Second) // warmup
	m.reset()
	measureStart := time.Now()
	time.Sleep(60 * time.Second) // measured window
	measureEnd := time.Now()
	close(stop)
	wg.Wait()

	for _, kind := range []string{"put", "get", "list", "vlist", "churn"} {
		m.setWindow(kind, measureStart, measureEnd)
	}
	mixed := m.summaries()
	peakMemLow := memAvailableMB()

	// --- contention storm: 200 concurrent commits to one key ------------------
	deadlocksBefore := s.pgDeadlocks(t)
	contentionKeys := intValueEnv("LOAD_CONTENTION", 200)
	var contention []time.Duration
	var contentionMu sync.Mutex
	var contentionErrs int64
	var maxLockWaiters int64
	lockSamplerDone := make(chan struct{})
	go func() {
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-lockSamplerDone:
				return
			case <-tick.C:
				waiters := s.pgLockWaiters(t)
				if waiters > atomic.LoadInt64(&maxLockWaiters) {
					atomic.StoreInt64(&maxLockWaiters, waiters)
				}
			}
		}
	}()
	var cwg sync.WaitGroup
	contentionStart := time.Now()
	for i := 0; i < contentionKeys; i++ {
		i := i
		cwg.Add(1)
		go func() {
			defer cwg.Done()
			key := "contention/hot"
			raw := []byte(fmt.Sprintf("contention-%d", i))
			start := time.Now()
			_, err := client(i).PutObject(ctx, mixedBucket, key, bytes.NewReader(raw), int64(len(raw)), "text/plain")
			contentionMu.Lock()
			contention = append(contention, time.Since(start))
			contentionMu.Unlock()
			if err != nil {
				atomic.AddInt64(&contentionErrs, 1)
			}
		}()
	}
	cwg.Wait()
	close(lockSamplerDone)
	contentionDur := time.Since(contentionStart)
	deadlocksAfterContention := s.pgDeadlocks(t)
	sort.Slice(contention, func(i, j int) bool { return contention[i] < contention[j] })
	contentionP99 := 0.0
	if len(contention) > 0 {
		contentionP99 = float64(contention[int(float64(len(contention)-1)*0.99)].Microseconds()) / 1000.0
	}

	// --- read-only phase: compare p99 against mixed ---------------------------
	mRO := newMeter()
	var roWg sync.WaitGroup
	roStop := make(chan struct{})
	for i := 0; i < 16; i++ {
		i := i
		roWg.Add(1)
		go func() {
			defer roWg.Done()
			rng := rand.New(rand.NewSource(int64(2000 + i)))
			for {
				select {
				case <-roStop:
					return
				default:
				}
				key := fmt.Sprintf("mixed/hot/%03d", rng.Intn(300))
				start := time.Now()
				body, err := client(i).GetObject(ctx, mixedBucket, key)
				var n int64
				if err == nil {
					raw, rerr := io.ReadAll(body)
					body.Close()
					n = int64(len(raw))
					if rerr != nil {
						err = rerr
					}
				}
				mRO.record("get", time.Since(start), n, err)
			}
		}()
	}
	roStart := time.Now()
	time.Sleep(10 * time.Second)
	roEnd := time.Now()
	close(roStop)
	roWg.Wait()
	mRO.setWindow("get", roStart, roEnd)
	readonly := mRO.summaries()
	deadlocksAfterRO := s.pgDeadlocks(t)

	// Stop continuous sampling now; the bloat wait below is a separate observation.
	close(samplerStop)
	<-samplerDone
	sampleMu.Lock()
	pgPeak = pgSnapshotSnapshot(pgPeak)
	sampleMu.Unlock()

	// --- correctness: verify sampled PUTs byte-identically --------------------
	mismatches := 0
	verified := 0
	for key, want := range ver.sample(verifySamples) {
		body, err := s.clients[0].GetObject(ctx, mixedBucket, key)
		if err != nil {
			mismatches++
			t.Logf("verification: GET %s: %v", key, err)
			continue
		}
		raw, err := io.ReadAll(body)
		body.Close()
		if err != nil {
			mismatches++
			continue
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != want {
			mismatches++
			t.Logf("verification: %s content mismatch", key)
		}
		verified++
	}
	// outage-time/churn keys are allowed to be absent; only put corpus is verified.

	// --- bloat / postgres final snapshot -------------------------------------
	// Wait for autovacuum to reclaim the churn (naptime is 5s in the container).
	bloatDeadline := time.Now().Add(60 * time.Second)
	var bloatFinal pgSnapshot
	for {
		bloatFinal = s.pgSnapshot(t)
		if bloatFinal.DeadTuples <= pgBase.DeadTuples+int64(0.5*float64(maxInt64(1, pgPeak.DeadTuples-pgBase.DeadTuples))) {
			break
		}
		if time.Now().After(bloatDeadline) {
			break
		}
		time.Sleep(2 * time.Second)
	}

	// --- repair/scrub must not fire ------------------------------------------
	repairOK := true
	var repair map[string]any
	if code, body := s.coordJSONGET("/v1/repair/status"); code == http.StatusOK {
		if json.Unmarshal(body, &repair) == nil {
			if shards, ok := repair["shardsets"].(map[string]any); ok {
				if u, ok := shards["unrecoverable"].(float64); ok && u > 0 {
					repairOK = false
				}
			}
		}
	}

	summary := buildReport(s, mixed, readonly, contentionP99, int64(len(contention)), contentionErrs, contentionDur, atomic.LoadInt64(&maxLockWaiters), deadlocksBefore, deadlocksAfterContention, deadlocksAfterRO, len(ver.m), verified, mismatches, pgBase, pgPeak, bloatFinal, baseMem, peakMemLow, minMem, repairOK, metricsBefore, s.coordMetricsText())

	path, err := writeReport(summary)
	if err != nil {
		t.Fatalf("write report: %v", err)
	}
	t.Logf("report: %s", path)
	printReport(t, summary)

	// --- hard correctness gates ----------------------------------------------
	if mismatches > 0 {
		t.Fatalf("CORRECTNESS: %d/%d sampled PUT->GET verifications mismatched", mismatches, verified)
	}
	if summary.Errors.NonRetryable5xx > 0 {
		t.Fatalf("CORRECTNESS: %d non-retryable 5xx responses (every 500 is a defect)", summary.Errors.NonRetryable5xx)
	}
	if summary.Contention.Deadlocks > 10 {
		t.Fatalf("CORRECTNESS: %d deadlocks in the contention phase (budget 10)", summary.Contention.Deadlocks)
	}
	if !summary.Bloat.Reclaimed {
		t.Fatalf("CORRECTNESS: kv n_dead_tup did not return toward baseline: baseline=%d peak=%d final=%d",
			summary.Bloat.Baseline, summary.Bloat.Peak, summary.Bloat.Final)
	}
	if !repairOK {
		t.Fatalf("CORRECTNESS: repair status reported unrecoverable shard sets during the run")
	}
	if summary.Pool.MaxConnections >= 200 {
		t.Fatalf("CORRECTNESS: PostgreSQL connection pool exhausted the server max_connections (%d)", summary.Pool.MaxConnections)
	}
}

func intValueEnv(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// coordJSONGET is a plain GET against the coordinator (no S3 signing needed for
// the internal API); used for version listings and repair status.
func (s *stack) coordJSONGET(path string) (int, []byte) {
	resp, err := http.Get(s.coordURL + path)
	if err != nil {
		return 0, []byte(err.Error())
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// ---------------------------------------------------------------------------
// Report types + assembly
// ---------------------------------------------------------------------------

type pgSnapshot struct {
	At          time.Time
	Active      int64 `json:"active"`
	Idle        int64 `json:"idle"`
	LockWaiters int64 `json:"lock_waiters"`
	DeadTuples  int64 `json:"dead_tuples"`
	Connections int64 `json:"connections"`
}

type report struct {
	StartedAt    time.Time             `json:"started_at"`
	Machine      string                `json:"machine"`
	Command      string                `json:"command"`
	Gateways     int                   `json:"gateways"`
	Memory       memoryReport          `json:"memory"`
	Mixed        map[string]latSummary `json:"mixed_phase"`
	ReadOnly     map[string]latSummary `json:"readonly_phase"`
	Contention   contentionReport      `json:"contention_phase"`
	Errors       errorsReport          `json:"errors"`
	Pool         poolReport            `json:"pool"`
	Bloat        bloatReport           `json:"bloat"`
	Postgres     postgresReport        `json:"postgres"`
	Verification verificationReport    `json:"verification"`
	Repair       bool                  `json:"repair_ok"`
	Coordinator  map[string]any        `json:"coordinator_metrics"`
	PhaseNotes   []string              `json:"phase_notes"`
}

type memoryReport struct {
	MemAvailableAtBootMB       int64 `json:"mem_available_at_boot_mb"`
	MemAvailableAfterMeasureMB int64 `json:"mem_available_after_measured_phase_mb"`
	MinAvailableMB             int64 `json:"min_available_mb"`
	GatewaysDegraded           bool  `json:"gateways_degraded_to_one"`
}

type contentionReport struct {
	Concurrency      int     `json:"concurrency"`
	DurationMS       float64 `json:"duration_ms"`
	P99MS            float64 `json:"p99_ms"`
	Errors           int64   `json:"errors"`
	Deadlocks        int64   `json:"deadlocks_delta"`
	MaxLockWaiters   int64   `json:"max_pg_lock_waiters"`
	DeadlocksAfterRO int64   `json:"deadlocks_after_readonly"`
}

type errorsReport struct {
	Retryable503    int64 `json:"503_retryable"`
	NonRetryable5xx int64 `json:"5xx_non_retryable"`
	Client4xx       int64 `json:"4xx"`
	Network         int64 `json:"network"`
}

type poolReport struct {
	MaxConnections int64 `json:"max_connections_observed"`
}

type bloatReport struct {
	Baseline  int64 `json:"baseline_dead_tuples"`
	Peak      int64 `json:"peak_dead_tuples"`
	Final     int64 `json:"final_dead_tuples"`
	Reclaimed bool  `json:"reclaimed"`
}

type postgresReport struct {
	MaxActive      int64 `json:"max_active_connections"`
	MaxLockWaiters int64 `json:"max_lock_waiters"`
	DeadlocksStart int64 `json:"deadlocks_start"`
	DeadlocksEnd   int64 `json:"deadlocks_end"`
}

type verificationReport struct {
	CorpusKeys int `json:"corpus_keys"`
	Verified   int `json:"verified"`
	Mismatches int `json:"mismatches"`
}

func buildReport(s *stack, mixed, readonly map[string]latSummary, contentionP99 float64, contentionN int64, contentionErrs int64, contentionDur time.Duration, maxLockWaiters int64, deadlocksBefore, deadlocksAfterContention, deadlocksAfterRO int64, corpus, verified, mismatches int, pgBase, pgPeak, bloatFinal pgSnapshot, baseMem, afterMem, minMem int64, repairOK bool, metricsBefore, metricsAfter string) report {
	r := report{
		StartedAt: time.Now().UTC(),
		Machine:   machineSpec(),
		Command:   "go test -tags=load -count=1 ./test/load/ -v",
		Gateways:  len(s.gateways),
		Mixed:     mixed,
		ReadOnly:  readonly,
		Contention: contentionReport{
			Concurrency: int(contentionN), DurationMS: float64(contentionDur.Microseconds()) / 1000.0,
			P99MS: contentionP99, Errors: contentionErrs,
			Deadlocks:      deadlocksAfterContention - deadlocksBefore,
			MaxLockWaiters: maxLockWaiters, DeadlocksAfterRO: deadlocksAfterRO,
		},
		Pool: poolReport{MaxConnections: pgPeak.Connections},
		Bloat: bloatReport{
			Baseline: pgBase.DeadTuples, Peak: pgPeak.DeadTuples, Final: bloatFinal.DeadTuples,
			Reclaimed: bloatFinal.DeadTuples <= pgBase.DeadTuples+int64(0.5*float64(maxInt64(1, pgPeak.DeadTuples-pgBase.DeadTuples))),
		},
		Postgres: postgresReport{
			MaxActive: pgPeak.Active, MaxLockWaiters: maxInt64(pgPeak.LockWaiters, maxLockWaiters),
			DeadlocksStart: deadlocksBefore, DeadlocksEnd: deadlocksAfterRO,
		},
		Verification: verificationReport{CorpusKeys: corpus, Verified: verified, Mismatches: mismatches},
		Repair:       repairOK,
		Coordinator:  parseCoordMetrics(metricsAfter),
		PhaseNotes: []string{
			"mixed: 32 PUT / 16 GET / 8 list (6 S3, 2 coordinator version-list) / 4 version-churn workers, 20s warmup + 60s measured",
			"contention: 200 concurrent PUTs to one key; pg_stat_activity sampled at 100ms for lock waiters",
			"readonly: 16 GET workers for 10s, compared against mixed GET p99",
			"bloat: n_dead_tup sampled after measured phases and after a wait for autovacuum (naptime=5s)",
			"12 MiB objects use single PUT via pkg/sdk; multipart is covered by test/compat, not this load profile",
		},
	}
	r.Memory = memoryReport{MemAvailableAtBootMB: baseMem, MemAvailableAfterMeasureMB: afterMem, MinAvailableMB: minMem, GatewaysDegraded: len(s.gateways) == 1}
	for _, phase := range []map[string]latSummary{mixed, readonly} {
		for _, st := range phase {
			r.Errors.Retryable503 += st.Err503
			r.Errors.NonRetryable5xx += st.Err5xx
			r.Errors.Client4xx += st.Err4xx
			r.Errors.Network += st.NetErrs
		}
	}
	return r
}

func machineSpec() string {
	raw, _ := os.ReadFile("/proc/cpuinfo")
	cpus := 0
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("processor")) {
			cpus++
		}
	}
	host, _ := os.Hostname()
	return fmt.Sprintf("host=%s cpus=%d docker=%s go=load", host, cpus, pgImage)
}

func parseCoordMetrics(text string) map[string]any {
	out := map[string]any{"scraped": len(text) > 0}
	for _, key := range []string{"fass_coordinator_http_requests_total", "fass_coordinator_http_request_duration_seconds_count"} {
		var sum float64
		for _, line := range bytes.Split([]byte(text), []byte("\n")) {
			fields := bytes.Fields(line)
			if len(fields) >= 2 && bytes.HasPrefix(fields[0], []byte(key)) {
				if v, err := jsonNumber(string(fields[len(fields)-1])); err == nil {
					sum += v
				}
			}
		}
		out[key] = sum
	}
	return out
}

func jsonNumber(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

// pgSnapshotNoFail is the sampler's variant: never fails the test on a transient
// connection error (the run's correctness gates are elsewhere).
func (s *stack) pgSnapshotNoFail() pgSnapshot {
	var snap pgSnapshot
	snap.At = time.Now()
	if s.pg == nil {
		return snap
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.pg.QueryRowContext(ctx, `SELECT
		count(*) FILTER (WHERE state='active'),
		count(*) FILTER (WHERE state='idle'),
		count(*) FILTER (WHERE wait_event_type='Lock'),
		count(*)
		FROM pg_stat_activity WHERE datname='fass'`).
		Scan(&snap.Active, &snap.Idle, &snap.LockWaiters, &snap.Connections)
	_ = s.pg.QueryRowContext(ctx, `SELECT COALESCE(SUM(n_dead_tup),0) FROM pg_stat_user_tables WHERE relname='kv'`).Scan(&snap.DeadTuples)
	return snap
}

func pgSnapshotSnapshot(p pgSnapshot) pgSnapshot { p.At = time.Now(); return p }

func (s *stack) pgSnapshot(t *testing.T) pgSnapshot {
	t.Helper()
	var snap pgSnapshot
	snap.At = time.Now()
	if s.pg == nil {
		return snap
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	row := s.pg.QueryRowContext(ctx, `SELECT
		count(*) FILTER (WHERE state='active'),
		count(*) FILTER (WHERE state='idle'),
		count(*) FILTER (WHERE wait_event_type='Lock'),
		count(*)
		FROM pg_stat_activity WHERE datname='fass'`)
	_ = row.Scan(&snap.Active, &snap.Idle, &snap.LockWaiters, &snap.Connections)
	_ = s.pg.QueryRowContext(ctx, `SELECT COALESCE(SUM(n_dead_tup),0) FROM pg_stat_user_tables WHERE relname='kv'`).Scan(&snap.DeadTuples)
	return snap
}

func (s *stack) pgDeadlocks(t *testing.T) int64 {
	t.Helper()
	var n int64
	_ = s.pg.QueryRow(`SELECT COALESCE(SUM(deadlocks),0) FROM pg_stat_database`).Scan(&n)
	return n
}

func (s *stack) pgLockWaiters(t *testing.T) int64 {
	t.Helper()
	var n int64
	_ = s.pg.QueryRow(`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND datname='fass'`).Scan(&n)
	return n
}

func (s *stack) coordMetricsText() string {
	resp, err := http.Get(s.coordURL + "/metrics")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return string(raw)
}

func (s *stack) dumpOnFailure(err error) {
	for _, p := range s.procs {
		fmt.Fprintf(os.Stderr, "\n---- %s (tail) ----\n%s\n", p.name, s.tail(p.name, 25))
	}
}

func writeReport(r report) (string, error) {
	dir := filepath.Join(root, "test", "load", "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("run-%s.json", r.StartedAt.Format("20060102T150405Z")))
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, raw, 0o644)
}

func printReport(t *testing.T, r report) {
	t.Helper()
	t.Logf("load profile: gateways=%d mem_at_boot=%dMB mem_after=%dMB", r.Gateways, r.Memory.MemAvailableAtBootMB, r.Memory.MemAvailableAfterMeasureMB)
	for _, phase := range []struct {
		name string
		m    map[string]latSummary
	}{{"mixed", r.Mixed}, {"readonly", r.ReadOnly}} {
		for kind, st := range phase.m {
			t.Logf("%s/%-6s n=%-7d err=%-6d(503=%d,5xx=%d,4xx=%d,net=%d) p50=%.1fms p95=%.1fms p99=%.1fms max=%.1fms rate=%.1fops/s %.2fMiB/s",
				phase.name, kind, st.N, st.Errors, st.Err503, st.Err5xx, st.Err4xx, st.NetErrs,
				st.P50ms, st.P95ms, st.P99ms, st.Maxms, st.OpsPerSec, st.MiBPerSec)
		}
	}
	t.Logf("contention: n=%d duration=%.1fms p99=%.1fms errors=%d deadlocks_delta=%d max_pg_lock_waiters=%d deadlocks_after_ro=%d",
		r.Contention.Concurrency, r.Contention.DurationMS, r.Contention.P99MS, r.Contention.Errors,
		r.Contention.Deadlocks, r.Contention.MaxLockWaiters, r.Contention.DeadlocksAfterRO)
	t.Logf("verification: %d/%d sampled byte-identical, mismatches=%d", r.Verification.Verified, r.Verification.CorpusKeys, r.Verification.Mismatches)
	t.Logf("postgres: max_active=%d max_lock_waiters=%d deadlocks %d->%d; pool max_conns=%d", r.Postgres.MaxActive, r.Postgres.MaxLockWaiters, r.Postgres.DeadlocksStart, r.Postgres.DeadlocksEnd, r.Pool.MaxConnections)
	t.Logf("bloat: n_dead_tup baseline=%d peak=%d final=%d reclaimed=%v", r.Bloat.Baseline, r.Bloat.Peak, r.Bloat.Final, r.Bloat.Reclaimed)
}
