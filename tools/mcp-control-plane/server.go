package main

import (
	"context"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	sessionCookie = "cp_session"
	csrfCookie    = "cp_csrf"
	minPassword   = 12
)

type ctxKey int

const userKey ctxKey = 0

type Server struct {
	store             *Store
	sessions          *Sessions
	tmpl              *template.Template
	limiter           *loginLimiter
	gatewayActorsPath string
	auditLogPath      string // read-only view of the gateway's hash-chained log

	// SSO (optional; configured in the admin UI).
	providers   *ProviderStore
	externalURL string
	flows       *flowStore
	oidcMu      sync.Mutex
	oidcCache   map[string]*oidc.Provider
}

func NewServer(store *Store, sessions *Sessions, gatewayActorsPath string) *Server {
	return &Server{
		store:             store,
		sessions:          sessions,
		tmpl:              template.Must(template.New("").Parse(templates)),
		limiter:           newLoginLimiter(10, 15*time.Minute),
		gatewayActorsPath: gatewayActorsPath,
		flows:             newFlowStore(),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/setup", s.handleSetup)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.Handle("/admin", s.requireAuth(http.HandlerFunc(s.handleAdmin)))
	mux.Handle("/admin/user/new", s.requireAdmin(http.HandlerFunc(s.handleUserNew)))
	mux.Handle("/admin/user", s.requireAdmin(http.HandlerFunc(s.handleUser)))
	mux.Handle("/admin/token", s.requireAuth(http.HandlerFunc(s.handleToken)))
	mux.Handle("/admin/audit", s.requireAdmin(http.HandlerFunc(s.handleAudit)))
	mux.Handle("/admin/sso", s.requireSuperAdmin(http.HandlerFunc(s.handleSSO)))
	// SSO login flow (public: these initiate/complete authentication).
	mux.HandleFunc("/auth/microsoft/start", s.handleSSOStart("microsoft"))
	mux.HandleFunc("/auth/microsoft/callback", s.handleSSOCallback("microsoft"))
	mux.HandleFunc("/auth/google/start", s.handleSSOStart("google"))
	mux.HandleFunc("/auth/google/callback", s.handleSSOCallback("google"))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	return mux
}

func (s *Server) requireSuperAdmin(next http.Handler) http.Handler {
	return s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.Context().Value(userKey).(*User)
		if u.Role != RoleSuperAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// syncGateway re-emits the actors file the gateway hot-reloads. Called after any
// change to users, grants, or tokens.
func (s *Server) syncGateway() {
	if err := writeGatewayActors(s.gatewayActorsPath, s.store.List()); err != nil {
		// Non-fatal: the change is saved in the store; the gateway file just
		// lags until the next successful write.
		_ = err
	}
}

func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return s.requireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := r.Context().Value(userKey).(*User)
		if !u.Role.isAdmin() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// ---- handlers ----

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	switch {
	case s.store.Count() == 0:
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
	case s.currentUser(r) != nil:
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	// First-run only: once any account exists, setup is closed forever.
	if s.store.Count() > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	csrf := s.ensureCSRF(w, r)
	if r.Method == http.MethodGet {
		s.render(w, "setup", map[string]any{"CSRF": csrf})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkCSRF(r) {
		s.render(w, "setup", map[string]any{"CSRF": csrf, "Error": "Session expired, try again."})
		return
	}
	email := normalizeEmail(r.FormValue("email"))
	name := strings.TrimSpace(r.FormValue("name"))
	pw := r.FormValue("password")
	confirm := r.FormValue("confirm")
	if msg := validateNewAccount(email, name, pw, confirm); msg != "" {
		s.render(w, "setup", map[string]any{"CSRF": csrf, "Error": msg})
		return
	}
	hash, err := HashPassword(pw)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Race guard: re-check emptiness under the store lock via Create failing if
	// somehow non-empty is not enough, so re-check count here too.
	if s.store.Count() > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if _, err := s.store.Create(&User{Email: email, Name: name, PasswordHash: hash, Role: RoleSuperAdmin}); err != nil {
		s.render(w, "setup", map[string]any{"CSRF": csrf, "Error": "Could not create account."})
		return
	}
	s.startSession(w, r, email)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.store.Count() == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	csrf := s.ensureCSRF(w, r)
	if r.Method == http.MethodGet {
		s.render(w, "login", map[string]any{"CSRF": csrf, "SSO": s.ssoButtons()})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	if !s.limiter.allow(ip) {
		s.render(w, "login", map[string]any{"CSRF": csrf, "Error": "Too many attempts. Wait a few minutes."})
		return
	}
	if !s.checkCSRF(r) {
		s.render(w, "login", map[string]any{"CSRF": csrf, "Error": "Session expired, try again."})
		return
	}
	email := normalizeEmail(r.FormValue("email"))
	pw := r.FormValue("password")
	u := s.store.ByEmail(email)
	if u == nil || u.Disabled || !VerifyPassword(pw, u.PasswordHash) {
		s.limiter.fail(ip)
		// One generic message: never reveal whether the email exists.
		s.render(w, "login", map[string]any{"CSRF": csrf, "Error": "Incorrect email or password."})
		return
	}
	s.limiter.reset(ip)
	s.startSession(w, r, u.Email)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(c.Value)
	}
	s.clearCookie(w, r, sessionCookie)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- auth plumbing ----

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := s.currentUser(r)
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}

func (s *Server) currentUser(r *http.Request) *User {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil
	}
	sess := s.sessions.Get(c.Value)
	if sess == nil {
		return nil
	}
	u := s.store.ByEmail(sess.Email)
	if u == nil || u.Disabled {
		return nil
	}
	return u
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, email string) {
	sess := s.sessions.Create(email)
	s.setCookie(w, r, sessionCookie, sess.Token, 12*time.Hour)
}

// ---- CSRF (double-submit cookie) ----

func (s *Server) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(csrfCookie); err == nil && c.Value != "" {
		return c.Value
	}
	tok := randToken()
	s.setCookie(w, r, csrfCookie, tok, 12*time.Hour)
	return tok
}

func (s *Server) checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil || c.Value == "" {
		return false
	}
	form := r.FormValue("csrf")
	return form != "" && subtleEqual(form, c.Value)
}

// ---- cookies ----

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: "/", HttpOnly: true,
		Secure: isSecure(r), SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// ---- helpers ----

func validateNewAccount(email, name, pw, confirm string) string {
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return "Enter a valid email address."
	}
	if name == "" {
		return "Enter your name."
	}
	if len(pw) < minPassword {
		return "Password must be at least 12 characters."
	}
	if pw != confirm {
		return "Passwords do not match."
	}
	return ""
}

func isSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// subtleEqual is a constant-time string compare.
func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// ---- login throttle ----

type loginLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	byIP   map[string]*attempts
}

type attempts struct {
	count int
	start time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, byIP: map[string]*attempts{}}
}

func (l *loginLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.byIP[ip]
	if a == nil || time.Since(a.start) > l.window {
		return true
	}
	return a.count < l.max
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.byIP[ip]
	if a == nil || time.Since(a.start) > l.window {
		l.byIP[ip] = &attempts{count: 1, start: time.Now()}
		return
	}
	a.count++
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	delete(l.byIP, ip)
	l.mu.Unlock()
}
