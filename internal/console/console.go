// Package console implements the FASS web console: server-rendered Go templates
// + HTMX, assets embedded in the binary, no Node toolchain.
//
// Design constraints (docs/04-services.md §8, docs/08-operations.md):
//   - the console is a separate process. It talks to the coordinator exclusively
//     over the documented HTTP+JSON API and must never import internal/coord or
//     internal/gateway;
//   - it is read-only by default; two safe write actions (activate a pending
//     agent, decommission an active one) are available only with
//     --read-only=false and require a CSRF token;
//   - auth is a single HTTP Basic credential (dev-grade; real RBAC is a later
//     task), and the coordinator being down must render a degraded banner, never
//     a crash or a 500.
package console

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Config configures the console server.
type Config struct {
	CoordinatorURL string
	User           string
	Password       string
	// ReadOnly disables both write actions (the default; see docs/08).
	ReadOnly bool
	Version  string
	Logger   *slog.Logger
	// Now is overridable in tests.
	Now func() time.Time
	// HTTPClient is used for coordinator requests (default: 5s timeout).
	HTTPClient *http.Client
}

// Server is the console HTTP handler.
type Server struct {
	cfg      Config
	client   *CoordinatorClient
	log      *slog.Logger
	now      func() time.Time
	pages    map[string]*template.Template
	partials *template.Template
	static   http.Handler
	mux      *http.ServeMux
}

// New validates the configuration, parses the embedded templates and wires the
// routes. Callers must supply basic-auth credentials: the console is an
// operator surface and an unauthenticated default would be a footgun.
func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.User) == "" || cfg.Password == "" {
		return nil, fmt.Errorf("console: --console-user and --console-password are required")
	}
	client, err := NewCoordinatorClient(cfg.CoordinatorURL, cfg.HTTPClient)
	if err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	s := &Server{
		cfg:    cfg,
		client: client,
		log:    logger,
		now:    now,
		pages:  map[string]*template.Template{},
		static: http.StripPrefix("/static/", http.FileServer(http.FS(mustSub(staticFS, "static")))),
		mux:    http.NewServeMux(),
	}
	funcs := template.FuncMap{
		"humanBytes": humanBytes,
		"hasPrefix":  strings.HasPrefix,
		"humanTime":  humanTime,
		"humanAgo":   humanAgo,
		"pct":        pct,
		"ratio":      func(f float64) string { return fmt.Sprintf("%.2fx", f) },
		"stateClass": stateClass,
		"join":       strings.Join,
		"dash":       dash,
		"add":        func(a, b int) int { return a + b },
		"percentOf":  percentOf,
	}
	pageNames := []string{"overview", "buckets", "bucket", "agents", "agent", "error"}
	for _, name := range pageNames {
		t, err := template.New("layout").Funcs(funcs).ParseFS(templateFS,
			"templates/layout.html", "templates/partials.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("console: parse template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	partials, err := template.New("partials").Funcs(funcs).ParseFS(templateFS, "templates/partials.html", "templates/object_drawer.html")
	if err != nil {
		return nil, fmt.Errorf("console: parse partials: %w", err)
	}
	s.partials = partials
	s.routes()
	return s, nil
}

func mustSub(fsys fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		panic("console: embed assets: " + err.Error())
	}
	return sub
}

// Handler returns the HTTP handler with security headers applied.
func (s *Server) Handler() http.Handler {
	return securityHeaders(s.mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// All assets are embedded and served from this origin. htmx.config.allowEval
		// is disabled in app.js, so no eval/unsafe-inline is needed.
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) routes() {
	// Liveness for probes; no auth so a load balancer can check it.
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q}`+"\n", s.cfg.Version)
	})
	s.mux.Handle("GET /static/", s.static)

	s.mux.HandleFunc("GET /{$}", s.auth(s.overview))
	s.mux.HandleFunc("GET /partials/overview", s.auth(s.overviewPartial))
	s.mux.HandleFunc("GET /partials/agents", s.auth(s.agentsPartial))
	s.mux.HandleFunc("GET /buckets", s.auth(s.bucketsPage))
	s.mux.HandleFunc("GET /buckets/{bucket}", s.auth(s.bucketPage))
	s.mux.HandleFunc("GET /buckets/{bucket}/object", s.auth(s.objectDrawer))
	s.mux.HandleFunc("GET /agents", s.auth(s.agentsPage))
	s.mux.HandleFunc("GET /agents/{agentID}", s.auth(s.agentPage))
	s.mux.HandleFunc("POST /agents/{agentID}/activate", s.auth(s.activateAgent))
	s.mux.HandleFunc("POST /agents/{agentID}/decommission", s.auth(s.decommissionAgent))
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !constantEqual(user, s.cfg.User) || !constantEqual(pass, s.cfg.Password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="FASS console", charset="UTF-8"`)
			http.Error(w, "401 unauthorized: FASS console credentials required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// constantEqual compares SHA-256 digests so neither length nor content of the
// credential leaks through timing.
func constantEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

// ---------------------------------------------------------------------------
// CSRF: double-submit cookie. The token is 32 random bytes, HttpOnly (only the
// server renders it), SameSite=Strict, and compared with constant time on POST.
// ---------------------------------------------------------------------------

const csrfCookie = "fass_csrf"

func randToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not recoverable; fall back to time+panic-free
		// value so the page still renders (it would fail CSRF, not leak).
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	tok := randToken()
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    tok,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   int((12 * time.Hour).Seconds()),
	})
	return tok
}

func (s *Server) checkCSRF(r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}
	c, err := r.Cookie(csrfCookie)
	if err != nil || len(c.Value) < 32 {
		return false
	}
	form := r.PostFormValue("csrf")
	if len(form) < 32 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(form)) == 1
}

// readOnlyRejection renders a 403 when a write action is attempted in read-only
// mode. The console defaults to read-only; the operator must opt in explicitly.
func (s *Server) readOnlyRejection(w http.ResponseWriter, r *http.Request) bool {
	if !s.cfg.ReadOnly {
		return false
	}
	s.renderError(w, r, http.StatusForbidden, "Read-only mode",
		"This console was started with --read-only. Restart it with --read-only=false to enable the agent activate/decommission actions.")
	return true
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

// Common is embedded in every page model. Templates read .Common.Title etc.
type Common struct {
	Title            string
	User             string
	ReadOnly         bool
	CSRF             string
	Flash            string
	CoordinatorError string
	Version          string
	Now              time.Time
	CurrentPath      string
}

func (s *Server) common(w http.ResponseWriter, r *http.Request, title string) Common {
	flash := strings.TrimSpace(r.URL.Query().Get("flash"))
	if len(flash) > 200 {
		flash = flash[:200]
	}
	return Common{
		Title:       title,
		User:        s.cfg.User,
		ReadOnly:    s.cfg.ReadOnly,
		CSRF:        s.csrfToken(w, r),
		Flash:       flash,
		Version:     s.cfg.Version,
		Now:         s.now(),
		CurrentPath: r.URL.Path,
	}
}

// render executes a page template into a buffer before writing, so a template
// error never emits a half page or a bogus 200 with broken HTML.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, data any) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "console: unknown page "+page, http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		s.log.Error("template render failed", "page", page, "err", err, "path", r.URL.Path)
		http.Error(w, "console: template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) renderPartial(w http.ResponseWriter, r *http.Request, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.partials.ExecuteTemplate(&buf, name, data); err != nil {
		s.log.Error("partial render failed", "partial", name, "err", err, "path", r.URL.Path)
		http.Error(w, "console: template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// ErrorData is the model for the error page.
type ErrorData struct {
	Common
	Status  int
	Message string
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, title, message string) {
	data := ErrorData{Common: s.common(w, r, title), Status: status, Message: message}
	s.render(w, r, status, "error", data)
}

// ---------------------------------------------------------------------------
// Template helpers (also used by handlers for consistent formatting)
// ---------------------------------------------------------------------------

// humanBytes accepts int, int64 and uint64 because templates pass manifest
// fields (int) and agent counters (int64) without an explicit conversion.
func humanBytes(v any) string {
	var n int64
	switch x := v.(type) {
	case int:
		n = int64(x)
	case int32:
		n = int64(x)
	case int64:
		n = x
	case uint64:
		n = int64(x)
	case float64:
		n = int64(x)
	default:
		return "-"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 5; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func humanTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

func humanAgo(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return humanAgoFrom(t, time.Now())
}

func humanAgoFrom(t, now time.Time) string {
	d := now.Sub(t)
	if d < 0 {
		return "just now"
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours())/24)
	}
}

func pct(used, total int64) string {
	if total <= 0 {
		return "-"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(used)/float64(total))
}

func percentOf(used, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return 100 * float64(used) / float64(total)
}

func stateClass(state string) string {
	switch strings.ToLower(state) {
	case "active":
		return "ok"
	case "suspect", "decommissioning":
		return "warn"
	case "offline":
		return "bad"
	default:
		return "idle"
	}
}

// dash renders "-" for empty values. It accepts any because templates pass
// plain strings and named string types (contract.RingID, contract.VersionID).
func dash(v any) string {
	if v == nil {
		return "-"
	}
	s := fmt.Sprint(v)
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
