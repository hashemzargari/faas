package console

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fass-storage/fass/internal/contract"
)

// ---------------------------------------------------------------------------
// View models
// ---------------------------------------------------------------------------

// OverviewData is the cluster overview page model.
type OverviewData struct {
	Common
	Status          string // ok | degraded | unreachable
	Health          map[string]any
	SnapshotAt      string
	AgentsTotal     int
	Active          int
	Suspect         int
	Offline         int
	Pending         int
	Decommissioning int
	CapacityBytes   int64
	UsedBytes       int64
	Rings           []RingView
	RCs             []RCView
	Nexuses         []NexusView
	Attention       []AttentionItem
	Coordinator5xx  int
	MetricsError    string
	// Repair is nil when the coordinator does not expose /v1/repair/status
	// (older release). Unknown (null) sub-fields render as "unknown".
	Repair *RepairStatus
	// Pre-formatted repair fields: null => "unknown", never 0/"no".
	RepairPresent       bool
	RepairCritical      bool
	RepairBacklog       string
	RepairRunning       string
	RepairFailed        string
	RepairOldest        string
	RepairBytes         string
	RepairThrottled     string
	RepairBudget        string
	RepairLastError     string
	RepairUnrecoverable string
	RepairBelowThresh   string
	RepairBelowWater    string
}

type RingView struct {
	Ring
	FullPct    float64
	AgentCount int
}

type RCView struct {
	RC    RedundancyClass
	Ratio float64
}

type NexusView struct {
	Nexus
	Agents int
	Active int
}

// AttentionItem is one line in the "needs attention" card.
type AttentionItem struct {
	Severity string // warn | bad
	Text     string
	Link     string
}

// AgentsData is the agents table model.
type AgentsData struct {
	Common
	Agents      []Agent
	Counts      map[string]int
	StateFilter string
	NexusFilter string
	Error       string
}

// BucketView is one row of the buckets table.
type BucketView struct {
	Config    contract.BucketConfig
	Objects   int
	Size      int64
	Truncated bool
}

// BucketsData is the buckets page model.
type BucketsData struct {
	Common
	Buckets []BucketView
	Error   string
}

// BucketPageData is the object browser model.
type BucketPageData struct {
	Common
	Bucket     contract.BucketConfig
	BucketName string
	Prefix     string
	Token      string
	Result     contract.ListResult
	NextToken  string
	Error      string
}

// ObjectDrawerData is the htmx object-metadata fragment model.
type ObjectDrawerData struct {
	Bucket   string
	Key      string
	Manifest contract.Manifest
	Error    string
}

// AgentPageData is the agent detail model.
type AgentPageData struct {
	Common
	AgentID   string
	Agent     Agent
	NexusName string
	NodeName  string
	Error     string
}

// ---------------------------------------------------------------------------
// Page handlers
// ---------------------------------------------------------------------------

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	data := s.buildOverview(w, r, s.common(w, r, "Overview"))
	s.render(w, r, http.StatusOK, "overview", data)
}

func (s *Server) overviewPartial(w http.ResponseWriter, r *http.Request) {
	data := s.buildOverview(w, r, s.common(w, r, "Overview"))
	s.renderPartial(w, r, http.StatusOK, "overview_body", data)
}

func (s *Server) buildOverview(w http.ResponseWriter, r *http.Request, common Common) OverviewData {
	d := OverviewData{Common: common, Status: "unreachable"}
	ctx := r.Context()

	health, err := s.client.Health(ctx)
	if err != nil {
		d.Common.CoordinatorError = err.Error()
		return d
	}
	d.Health = health

	snap, err := s.client.Topology(ctx)
	if err != nil {
		d.Common.CoordinatorError = err.Error()
		return d
	}
	d.SnapshotAt = humanTime(snap.At)
	d.AgentsTotal = len(snap.Agents)
	counts := snap.CountByState()
	d.Active, d.Suspect, d.Offline = counts["active"], counts["suspect"], counts["offline"]
	d.Pending, d.Decommissioning = counts["pending"], counts["decommissioning"]
	d.UsedBytes, d.CapacityBytes = snap.Capacity()

	agentsByNexus := map[string]int{}
	activeByNexus := map[string]int{}
	for _, a := range snap.Agents {
		agentsByNexus[a.NexusID]++
		if strings.EqualFold(a.State, "active") {
			activeByNexus[a.NexusID]++
		}
	}
	nexuses := append([]Nexus(nil), snap.Nexuses...)
	sort.Slice(nexuses, func(i, j int) bool { return nexuses[i].ID < nexuses[j].ID })
	for _, n := range nexuses {
		d.Nexuses = append(d.Nexuses, NexusView{Nexus: n, Agents: agentsByNexus[n.ID], Active: activeByNexus[n.ID]})
		if n.WriteDegraded {
			d.Attention = append(d.Attention, AttentionItem{Severity: "warn", Text: "Nexus " + n.ID + " is write-degraded", Link: "/agents"})
		}
		if agentsByNexus[n.ID] == 0 {
			d.Attention = append(d.Attention, AttentionItem{Severity: "warn", Text: "Nexus " + n.ID + " has no agents", Link: "/agents"})
		}
	}

	rings := append([]Ring(nil), snap.Rings...)
	sort.Slice(rings, func(i, j int) bool { return rings[i].ID < rings[j].ID })
	for _, ring := range rings {
		rv := RingView{Ring: ring, FullPct: ring.FullPct(), AgentCount: len(ring.AgentIDs)}
		d.Rings = append(d.Rings, rv)
		if rv.FullPct >= 85 {
			d.Attention = append(d.Attention, AttentionItem{Severity: "warn", Text: "Ring " + ring.ID + " is " + pct(ring.UsedBytes, ring.Capacity) + " full", Link: "/agents"})
		}
	}

	rcs := append([]RedundancyClass(nil), snap.RedundancyClasses...)
	sort.Slice(rcs, func(i, j int) bool { return rcs[i].ID < rcs[j].ID })
	for _, rc := range rcs {
		d.RCs = append(d.RCs, RCView{RC: rc, Ratio: rc.Ratio()})
	}

	for _, a := range sortedAgents(snap.Agents) {
		switch strings.ToLower(a.State) {
		case "offline":
			d.Attention = append(d.Attention, AttentionItem{Severity: "bad", Text: "Agent " + a.ID + " (" + a.NexusID + "/" + a.NodeID + ") is OFFLINE", Link: "/agents/" + url.PathEscape(a.ID)})
		case "suspect":
			d.Attention = append(d.Attention, AttentionItem{Severity: "warn", Text: "Agent " + a.ID + " (" + a.NexusID + "/" + a.NodeID + ") is SUSPECT", Link: "/agents/" + url.PathEscape(a.ID)})
		}
	}

	if rs, rerr := s.client.RepairStatus(ctx); rerr == nil {
		d.Repair = &rs
		d.RepairPresent = true
		d.RepairBacklog = unknownOrInt(ptrSum(rs.QueueField("pending"), rs.QueueField("running")))
		d.RepairRunning = unknownOrInt(rs.QueueField("running"))
		d.RepairFailed = unknownOrInt(rs.QueueField("failed"))
		d.RepairOldest = unknownOrSeconds(rs.OldestPendingAgeSeconds)
		d.RepairBytes = unknownOrBytes(rs.BytesRepairedLast24h)
		d.RepairThrottled = unknownOrBool(rs.Throttled)
		d.RepairBudget = unknownOrInt64(rs.PerSiteBudgetMbps)
		d.RepairLastError = unknownOrText(rs.LastError)
		d.RepairUnrecoverable = unknownOrInt(rs.ShardSetField("unrecoverable"))
		d.RepairBelowThresh = unknownOrInt(rs.ShardSetField("below_threshold"))
		d.RepairBelowWater = unknownOrInt(rs.ShardSetField("below_repair_watermark"))
		if unrecoverable, ok := rs.Unrecoverable(); ok && unrecoverable > 0 {
			d.RepairCritical = true
			// The only number that means data loss has already happened.
			d.Attention = append([]AttentionItem{{Severity: "bad", Text: fmt.Sprintf("DATA LOSS: %d shard set(s) are UNRECOVERABLE (fewer than geo_n reachable groups) — escalate immediately", unrecoverable), Link: "/agents"}}, d.Attention...)
		} else if backlog, ok := rs.Backlog(); ok && backlog > 0 {
			d.Attention = append(d.Attention, AttentionItem{Severity: "warn", Text: fmt.Sprintf("Repair backlog: %d job(s) pending or running", backlog), Link: "/agents"})
		}
		if rs.Queue != nil && rs.Queue.Failed != nil && *rs.Queue.Failed > 0 {
			d.Attention = append(d.Attention, AttentionItem{Severity: "warn", Text: fmt.Sprintf("%d repair job(s) failed", *rs.Queue.Failed), Link: "/agents"})
		}
	}
	if raw, merr := s.client.Metrics(ctx); merr != nil {
		d.MetricsError = merr.Error()
	} else {
		d.Coordinator5xx = countServerErrors(raw)
	}

	d.Status = "ok"
	if d.Offline > 0 || d.Suspect > 0 || len(d.Attention) > 0 {
		d.Status = "degraded"
	}
	if d.Repair != nil {
		if unrecoverable, ok := d.Repair.Unrecoverable(); ok && unrecoverable > 0 {
			d.Status = "critical"
		}
	}
	return d
}

// countServerErrors sums coordinator HTTP 5xx counters from the Prometheus
// exposition. There is no "recent errors" API; the counters are the honest
// substitute and the console labels them as such.
func countServerErrors(raw string) int {
	total := 0
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "fass_coordinator_http_requests_total{") {
			continue
		}
		idx := strings.Index(line, `status="`)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(`status="`):]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			continue
		}
		status, err := strconv.Atoi(rest[:end])
		if err != nil || status < 500 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		v, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			continue
		}
		total += v
	}
	return total
}

func (s *Server) agentsPage(w http.ResponseWriter, r *http.Request) {
	data := s.buildAgents(w, r, s.common(w, r, "Agents"))
	s.render(w, r, http.StatusOK, "agents", data)
}

func (s *Server) agentsPartial(w http.ResponseWriter, r *http.Request) {
	data := s.buildAgents(w, r, s.common(w, r, "Agents"))
	s.renderPartial(w, r, http.StatusOK, "agents_body", data)
}

func (s *Server) buildAgents(w http.ResponseWriter, r *http.Request, common Common) AgentsData {
	d := AgentsData{Common: common, Counts: map[string]int{}}
	d.StateFilter = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	d.NexusFilter = strings.TrimSpace(r.URL.Query().Get("nexus"))

	snap, err := s.client.Topology(r.Context())
	if err != nil {
		d.Common.CoordinatorError = err.Error()
		return d
	}
	d.Counts = snap.CountByState()
	for _, a := range sortedAgents(snap.Agents) {
		if d.StateFilter != "" && strings.ToLower(a.State) != d.StateFilter {
			continue
		}
		if d.NexusFilter != "" && a.NexusID != d.NexusFilter {
			continue
		}
		d.Agents = append(d.Agents, a)
	}
	return d
}

func (s *Server) bucketsPage(w http.ResponseWriter, r *http.Request) {
	data := BucketsData{Common: s.common(w, r, "Buckets")}
	ctx := r.Context()
	buckets, err := s.client.Buckets(ctx)
	if err != nil {
		data.Common.CoordinatorError = err.Error()
		s.render(w, r, http.StatusOK, "buckets", data)
		return
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Name < buckets[j].Name })
	for _, b := range buckets {
		view := BucketView{Config: b}
		// One page of metadata is enough for an at-a-glance count; when there are
		// more objects the console says "1000+" rather than paginating every
		// bucket on every page load.
		res, lerr := s.client.ListObjects(ctx, b.Name, "", "", 1000)
		if lerr == nil {
			view.Objects = len(res.Entries)
			for _, e := range res.Entries {
				view.Size += e.Size
			}
			view.Truncated = res.IsTruncated
		}
		data.Buckets = append(data.Buckets, view)
	}
	s.render(w, r, http.StatusOK, "buckets", data)
}

func (s *Server) bucketPage(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	data := BucketPageData{
		Common:     s.common(w, r, "Bucket "+bucket),
		BucketName: bucket,
		Prefix:     r.URL.Query().Get("prefix"),
		Token:      r.URL.Query().Get("token"),
	}
	ctx := r.Context()
	cfg, err := s.client.Bucket(ctx, bucket)
	if err != nil {
		data.Common.CoordinatorError = err.Error()
		s.render(w, r, http.StatusOK, "bucket", data)
		return
	}
	data.Bucket = cfg
	res, err := s.client.ListObjects(ctx, bucket, data.Prefix, data.Token, 100)
	if err != nil {
		data.Common.CoordinatorError = err.Error()
		s.render(w, r, http.StatusOK, "bucket", data)
		return
	}
	data.Result = res
	if res.IsTruncated {
		data.NextToken = res.NextContinuationToken
	}
	s.render(w, r, http.StatusOK, "bucket", data)
}

func (s *Server) objectDrawer(w http.ResponseWriter, r *http.Request) {
	bucket := r.PathValue("bucket")
	key := r.URL.Query().Get("key")
	version := r.URL.Query().Get("version")
	data := ObjectDrawerData{Bucket: bucket, Key: key}
	if key == "" {
		data.Error = "missing object key"
		s.renderPartial(w, r, http.StatusBadRequest, "object_drawer", data)
		return
	}
	m, err := s.client.Manifest(r.Context(), bucket, key, version)
	if err != nil {
		data.Error = err.Error()
		s.renderPartial(w, r, http.StatusOK, "object_drawer", data)
		return
	}
	data.Manifest = m
	s.renderPartial(w, r, http.StatusOK, "object_drawer", data)
}

func (s *Server) agentPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("agentID")
	data := AgentPageData{Common: s.common(w, r, "Agent "+id), AgentID: id}
	ctx := r.Context()
	ag, err := s.client.Agent(ctx, id)
	if err != nil {
		data.Common.CoordinatorError = err.Error()
		s.render(w, r, http.StatusOK, "agent", data)
		return
	}
	data.Agent = ag
	if snap, terr := s.client.Topology(ctx); terr == nil {
		for _, n := range snap.Nexuses {
			if n.ID == ag.NexusID {
				data.NexusName = n.Name
			}
		}
		for _, n := range snap.Nodes {
			if n.ID == ag.NodeID {
				data.NodeName = n.Hostname
			}
		}
	}
	s.render(w, r, http.StatusOK, "agent", data)
}

// ---------------------------------------------------------------------------
// Write actions
// ---------------------------------------------------------------------------

func (s *Server) activateAgent(w http.ResponseWriter, r *http.Request) {
	if s.readOnlyRejection(w, r) {
		return
	}
	if !s.checkCSRF(r) {
		s.renderError(w, r, http.StatusForbidden, "CSRF check failed",
			"The form's CSRF token did not match the console cookie. Reload the page and try again.")
		return
	}
	id := r.PathValue("agentID")
	if err := s.client.ActivateAgent(r.Context(), id); err != nil {
		s.renderError(w, r, http.StatusBadGateway, "Activation failed", err.Error())
		return
	}
	s.log.Info("agent activated from console", "agent_id", id, "user", s.cfg.User)
	http.Redirect(w, r, "/agents?flash="+url.QueryEscape("Agent "+id+" activated"), http.StatusSeeOther)
}

func (s *Server) decommissionAgent(w http.ResponseWriter, r *http.Request) {
	if s.readOnlyRejection(w, r) {
		return
	}
	if !s.checkCSRF(r) {
		s.renderError(w, r, http.StatusForbidden, "CSRF check failed",
			"The form's CSRF token did not match the console cookie. Reload the page and try again.")
		return
	}
	id := r.PathValue("agentID")
	// `on=false` is offered on the detail page so an accidental decommission can
	// be cancelled before the agent goes offline for good.
	on := true
	if r.PostFormValue("on") == "false" {
		on = false
	}
	if err := s.client.DecommissionAgent(r.Context(), id, on); err != nil {
		s.renderError(w, r, http.StatusBadGateway, "Decommission failed", err.Error())
		return
	}
	action := "decommissioning started for "
	if !on {
		action = "decommissioning cancelled for "
	}
	s.log.Info("agent decommission changed from console", "agent_id", id, "on", on, "user", s.cfg.User)
	http.Redirect(w, r, "/agents?flash="+url.QueryEscape(action+id), http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// Repair-status formatting helpers: nil means "unknown", never zero.
// ---------------------------------------------------------------------------

// QueueField exists on RepairStatus as a small accessor for templates? No:
// handlers format from the struct directly below.
func ptrSum(a, b *int) *int {
	if a == nil || b == nil {
		return nil
	}
	v := *a + *b
	return &v
}

func unknownOrInt(v *int) string {
	if v == nil {
		return "unknown"
	}
	return strconv.Itoa(*v)
}

func unknownOrInt64(v *int64) string {
	if v == nil {
		return "unknown"
	}
	return strconv.FormatInt(*v, 10)
}

func unknownOrBool(v *bool) string {
	if v == nil {
		return "unknown"
	}
	if *v {
		return "yes"
	}
	return "no"
}

func unknownOrSeconds(v *float64) string {
	if v == nil {
		return "unknown"
	}
	return (time.Duration(*v * float64(time.Second))).Round(time.Second).String()
}

func unknownOrBytes(v *int64) string {
	if v == nil {
		return "unknown"
	}
	return humanBytes(*v)
}

func unknownOrText(v *string) string {
	if v == nil || strings.TrimSpace(*v) == "" {
		return "-"
	}
	return *v
}
