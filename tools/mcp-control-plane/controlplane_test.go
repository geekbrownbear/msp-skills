package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery staple", h) {
		t.Fatal("valid password did not verify")
	}
	if VerifyPassword("wrong password entirely", h) {
		t.Fatal("wrong password verified")
	}
	if VerifyPassword("x", "not-a-phc-string") {
		t.Fatal("garbage hash verified")
	}
}

func TestStoreCreateUniqueEmail(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if s.Count() != 0 {
		t.Fatalf("fresh store not empty")
	}
	if _, err := s.Create(&User{Email: "A@Bearium.net", Name: "A", PasswordHash: "h", Role: RoleSuperAdmin}); err != nil {
		t.Fatal(err)
	}
	if s.ByEmail("a@bearium.net") == nil {
		t.Fatal("email not normalized/stored")
	}
	if _, err := s.Create(&User{Email: "a@bearium.net", Name: "dup", PasswordHash: "h"}); err != errEmailTaken {
		t.Fatalf("expected errEmailTaken, got %v", err)
	}
	// Reload from disk to confirm persistence.
	s2, err := NewStore(dirOf(s))
	if err != nil {
		t.Fatal(err)
	}
	if s2.Count() != 1 {
		t.Fatalf("persistence failed: got %d", s2.Count())
	}
}

func dirOf(s *Store) string {
	i := strings.LastIndex(s.path, "/")
	return s.path[:i]
}

// jarClient returns an http client that follows redirects and keeps cookies,
// plus a helper to read the CSRF cookie value the server set.
func newTestServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(store, NewSessions(time.Hour), "")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	return ts, &http.Client{Jar: jar}
}

func csrfFromJar(t *testing.T, c *http.Client, base string) string {
	t.Helper()
	u, _ := url.Parse(base)
	for _, ck := range c.Jar.Cookies(u) {
		if ck.Name == csrfCookie {
			return ck.Value
		}
	}
	t.Fatal("no csrf cookie set")
	return ""
}

func TestSetupAndLoginFlow(t *testing.T) {
	ts, c := newTestServer(t)

	// Root with no users -> setup form.
	resp, err := c.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.HasSuffix(resp.Request.URL.Path, "/setup") {
		t.Fatalf("empty store should land on /setup, got %s", resp.Request.URL.Path)
	}
	csrf := csrfFromJar(t, c, ts.URL)

	// Create the super admin.
	post(t, c, ts.URL+"/setup", url.Values{
		"csrf": {csrf}, "name": {"Abhi"}, "email": {"abhi@bearium.net"},
		"password": {"a-very-long-password"}, "confirm": {"a-very-long-password"},
	}, "/admin")

	// /admin is reachable and shows the account.
	body := get(t, c, ts.URL+"/admin", "/admin")
	if !strings.Contains(body, "abhi@bearium.net") || !strings.Contains(body, "superadmin") {
		t.Fatalf("admin page missing account/role: %s", body)
	}

	// Setup is now closed.
	if p := get(t, c, ts.URL+"/setup", ""); strings.Contains(p, "Create the super admin") {
		t.Fatal("setup should be closed once an account exists")
	}

	// Log out, then /admin bounces to /login.
	post(t, c, ts.URL+"/logout", url.Values{}, "/login")
	if got := getPath(t, c, ts.URL+"/admin"); got != "/login" {
		t.Fatalf("logged out /admin should redirect to /login, got %s", got)
	}

	// Wrong password rejected; right password accepted.
	csrf = csrfFromJar(t, c, ts.URL) // refresh after visiting /login
	getPath(t, c, ts.URL+"/login")
	csrf = csrfFromJar(t, c, ts.URL)
	if b := postRaw(t, c, ts.URL+"/login", url.Values{"csrf": {csrf}, "email": {"abhi@bearium.net"}, "password": {"nope"}}); !strings.Contains(b, "Incorrect email or password") {
		t.Fatalf("wrong password should error, got %s", b)
	}
	post(t, c, ts.URL+"/login", url.Values{"csrf": {csrf}, "email": {"abhi@bearium.net"}, "password": {"a-very-long-password"}}, "/admin")
}

func TestBuildGatewayActors(t *testing.T) {
	users := []*User{
		{Email: "u@b.net", Name: "U", Role: RoleUser,
			Grants: map[string]CPGrant{"halopsa": {Access: "read"}, "quickbooks": {Access: "none"}, "immybot": {Access: "write"}},
			Tokens: []TokenRef{{Hash: "deadbeef", Label: "laptop"}}},
		{Email: "admin@b.net", Name: "Admin", Role: RoleSuperAdmin},
		{Email: "d@b.net", Name: "D", Role: RoleUser, Disabled: true},
	}
	acts := buildGatewayActors(users)
	if len(acts) != 3 { // u -> email + 1 token; admin -> email; d disabled -> none
		t.Fatalf("want 3 actors, got %d", len(acts))
	}
	email := map[string]gwActor{}
	var tokenActor gwActor
	for _, a := range acts {
		if a.TokenSHA256 != "" {
			tokenActor = a
		} else {
			email[a.Email] = a
		}
	}
	// Regular user: only explicit grants, and not an admin.
	u := email["u@b.net"]
	if u.Admin {
		t.Fatalf("regular user must not carry the admin flag")
	}
	if g, ok := u.Grants["halopsa"]; !ok || g.Write {
		t.Fatalf("halopsa should be read-only: %+v", u.Grants)
	}
	if g, ok := u.Grants["immybot"]; !ok || !g.Write {
		t.Fatalf("immybot should be write: %+v", u.Grants)
	}
	if _, ok := u.Grants["quickbooks"]; ok {
		t.Fatalf("quickbooks 'none' should be omitted")
	}
	// Admin: full write on every connector, no hand-granting needed.
	adm := email["admin@b.net"]
	if !adm.Admin {
		t.Fatalf("super admin should carry the admin flag")
	}
	if len(adm.Grants) != len(connectors()) {
		t.Fatalf("admin should get all %d connectors, got %d", len(connectors()), len(adm.Grants))
	}
	for _, c := range connectors() {
		if g, ok := adm.Grants[c.Slug]; !ok || !g.Write {
			t.Fatalf("admin should have write on %q, got %+v", c.Slug, adm.Grants[c.Slug])
		}
	}
	// Token actor inherits its owner's identity.
	if tokenActor.TokenSHA256 != "deadbeef" || tokenActor.Email != "u@b.net" {
		t.Fatalf("token actor wrong: %+v", tokenActor)
	}
}

func TestAdminCreatesUserSetsPermissionsEmitsActors(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	gwPath := dir + "/actors.json"
	srv := NewServer(store, NewSessions(time.Hour), gwPath)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	c.Get(ts.URL + "/")
	csrf := csrfFromJar(t, c, ts.URL)
	post(t, c, ts.URL+"/setup", url.Values{"csrf": {csrf}, "name": {"Admin"}, "email": {"admin@b.net"},
		"password": {"a-very-long-password"}, "confirm": {"a-very-long-password"}}, "/admin")

	csrf = csrfFromJar(t, c, ts.URL)
	post(t, c, ts.URL+"/admin/user/new", url.Values{"csrf": {csrf}, "name": {"Jane"}, "email": {"jane@b.net"},
		"role": {"user"}, "password": {"another-long-pass"}}, "/admin/user")

	csrf = csrfFromJar(t, c, ts.URL)
	post(t, c, ts.URL+"/admin/user?email=jane@b.net", url.Values{"csrf": {csrf}, "action": {"permissions"},
		"grant_halopsa": {"read"}, "grant_immybot": {"write"}, "grant_quickbooks": {"none"}}, "/admin/user")

	j := store.ByEmail("jane@b.net")
	if j == nil || j.Grants["halopsa"].Access != "read" || j.Grants["immybot"].Access != "write" {
		t.Fatalf("grants not saved: %+v", j)
	}
	rawB, err := os.ReadFile(gwPath)
	if err != nil {
		t.Fatalf("actors file not written: %v", err)
	}
	raw := string(rawB)
	if !strings.Contains(raw, "jane@b.net") || !strings.Contains(raw, "halopsa") {
		t.Fatalf("actors file missing jane/halopsa: %s", raw)
	}
}

// ---- test helpers ----

func TestProviderStoreAndIssuer(t *testing.T) {
	dir := t.TempDir()
	ps, err := NewProviderStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.Save(SSOConfig{Microsoft: ProviderConfig{Enabled: true, ClientID: "cid", ClientSecret: "sec", TenantID: "tid", AllowedDomains: []string{"bearium.net"}}}); err != nil {
		t.Fatal(err)
	}
	ps2, err := NewProviderStore(dir) // reload from disk
	if err != nil {
		t.Fatal(err)
	}
	ms := ps2.Get().Microsoft
	if !ms.ready() || ms.ClientSecret != "sec" {
		t.Fatalf("secret/ready not persisted: %+v", ms)
	}
	if got := ms.issuer("microsoft"); got != "https://login.microsoftonline.com/tid/v2.0" {
		t.Fatalf("issuer wrong: %s", got)
	}
}

func TestDomainAllowed(t *testing.T) {
	if !domainAllowed("Jane@Bearium.net", []string{"bearium.net"}) {
		t.Fatal("case-insensitive domain should be allowed")
	}
	if domainAllowed("x@evil.test", []string{"bearium.net"}) {
		t.Fatal("off-domain should be denied")
	}
	if domainAllowed("no-at-sign", []string{"bearium.net"}) {
		t.Fatal("malformed email should be denied")
	}
	if domainAllowed("x@bearium.net", nil) {
		t.Fatal("empty allowlist should deny (no auto-provision)")
	}
}

func TestSSOLoginMapping(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	ps, _ := NewProviderStore(dir)
	ps.Save(SSOConfig{Microsoft: ProviderConfig{Enabled: true, ClientID: "x", ClientSecret: "y", AllowedDomains: []string{"bearium.net"}}})
	srv := NewServer(store, NewSessions(time.Hour), dir+"/actors.json")
	srv.providers = ps

	run := func(email string) (created bool, failMsg string) {
		before := store.Count()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/auth/microsoft/callback", nil)
		srv.ssoLogin(w, r, "microsoft", email, "Name", "", func(m string) { failMsg = m })
		return store.Count() > before, failMsg
	}

	// Allowed domain, unknown user -> auto-provisioned as 'user'.
	if created, fail := run("new@bearium.net"); !created || fail != "" {
		t.Fatalf("expected auto-provision, created=%v fail=%q", created, fail)
	}
	if u := store.ByEmail("new@bearium.net"); u == nil || u.Role != RoleUser {
		t.Fatalf("provisioned account wrong: %+v", u)
	}
	// Existing user -> login, no new account.
	if created, fail := run("new@bearium.net"); created || fail != "" {
		t.Fatalf("existing user should log in without creating; created=%v fail=%q", created, fail)
	}
	// Off-domain unknown user -> denied, no account.
	if created, fail := run("mallory@evil.test"); created || fail == "" {
		t.Fatalf("off-domain should be denied; created=%v fail=%q", created, fail)
	}
}

func TestReadAuditChain(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	auditLine := func(seq int64, prev string) []byte {
		e := map[string]any{
			"seq": seq, "prev_sha256": prev, "ts": "2026-09-04T00:00:00Z",
			"actor":     map[string]any{"email": "a@bearium.net", "name": "A"},
			"connector": "halopsa",
			"mcp":       map[string]any{"method": "tools/call", "tool": "tickets"},
			"policy":    map[string]any{"decision": "allow", "class": "read"},
		}
		b, _ := json.Marshal(e)
		return b
	}
	sha := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

	l1 := auditLine(1, "")
	l2 := auditLine(2, sha(l1))
	if err := os.WriteFile(path, []byte(string(l1)+"\n"+string(l2)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := readAudit(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.ChainOK || rep.Total != 2 {
		t.Fatalf("valid chain expected ok/2, got %+v", rep)
	}
	if rep.Events[0].Seq != 2 || rep.Events[0].Actor.Email != "a@bearium.net" {
		t.Fatalf("newest-first parse wrong: %+v", rep.Events[0])
	}

	bad := auditLine(2, "deadbeefdeadbeef")
	if err := os.WriteFile(path, []byte(string(l1)+"\n"+string(bad)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rep2, _ := readAudit(path, 10); rep2.ChainOK {
		t.Fatal("tampered chain should be reported broken")
	}
}

func post(t *testing.T, c *http.Client, u string, v url.Values, wantPath string) {
	t.Helper()
	resp, err := c.PostForm(u, v)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if wantPath != "" && resp.Request.URL.Path != wantPath {
		t.Fatalf("POST %s: expected to land on %s, got %s (status %d)", u, wantPath, resp.Request.URL.Path, resp.StatusCode)
	}
}

func postRaw(t *testing.T, c *http.Client, u string, v url.Values) string {
	t.Helper()
	resp, err := c.PostForm(u, v)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return readAll(t, resp)
}

func get(t *testing.T, c *http.Client, u, wantPath string) string {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if wantPath != "" && resp.Request.URL.Path != wantPath {
		t.Fatalf("GET %s landed on %s, want %s", u, resp.Request.URL.Path, wantPath)
	}
	return readAll(t, resp)
}

func getPath(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.Request.URL.Path
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return string(buf)
}

// verifyTestTicket mirrors what a delegated app (Callisto) does to validate a
// ticket: recompute the HMAC over part1, constant-time compare, then decode.
func verifyTestTicket(key []byte, tok string) (ticketClaims, error) {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		return ticketClaims{}, fmt.Errorf("bad format")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[0]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return ticketClaims{}, fmt.Errorf("bad signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ticketClaims{}, err
	}
	var c ticketClaims
	if err := json.Unmarshal(raw, &c); err != nil {
		return ticketClaims{}, err
	}
	return c, nil
}

func TestDelegatedSSOAuthorize(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir)
	store.Create(&User{Email: "a@bearium.net", Name: "A", PasswordHash: "h", Role: RoleSuperAdmin})
	srv := NewServer(store, NewSessions(time.Hour), dir+"/actors.json")
	key := []byte("shared-ticket-key")
	srv.ssoTicketKey = key
	srv.ssoAllowedRedirects = []string{"https://app.example/auth/callback"}

	// A valid session cookie for the authed cases.
	sw := httptest.NewRecorder()
	srv.startSession(sw, httptest.NewRequest(http.MethodGet, "/", nil), "a@bearium.net")
	cookie := sw.Result().Cookies()[0]
	allowed := url.QueryEscape("https://app.example/auth/callback")

	// Unauthenticated -> bounce to login, returning here afterwards.
	r := httptest.NewRequest(http.MethodGet, "/sso/authorize?redirect_uri="+allowed+"&state=xyz", nil)
	w := httptest.NewRecorder()
	srv.handleSSOAuthorize(w, r)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/login?next=") {
		t.Fatalf("unauth: want redirect to /login, got %d %s", w.Code, w.Header().Get("Location"))
	}

	// Authenticated but disallowed redirect_uri -> 400 (no ticket leaks).
	r = httptest.NewRequest(http.MethodGet, "/sso/authorize?redirect_uri="+url.QueryEscape("https://evil.example/x")+"&state=xyz", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	srv.handleSSOAuthorize(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad redirect_uri: want 400, got %d", w.Code)
	}

	// Authenticated + allowed -> redirect to the app with a verifiable ticket.
	r = httptest.NewRequest(http.MethodGet, "/sso/authorize?redirect_uri="+allowed+"&state=xyz", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	srv.handleSSOAuthorize(w, r)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("authed: want 303, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("state") != "xyz" {
		t.Fatalf("state not echoed back: %s", w.Header().Get("Location"))
	}
	claims, err := verifyTestTicket(key, loc.Query().Get("ticket"))
	if err != nil {
		t.Fatalf("ticket did not verify: %v", err)
	}
	if claims.Email != "a@bearium.net" || claims.Role != string(RoleSuperAdmin) {
		t.Fatalf("ticket claims wrong: %+v", claims)
	}
	if claims.Exp <= time.Now().Unix() {
		t.Fatalf("ticket already expired: exp=%d", claims.Exp)
	}

	// A tampered signature must fail.
	if _, err := verifyTestTicket(key, loc.Query().Get("ticket")+"x"); err == nil {
		t.Fatalf("tampered ticket verified")
	}

	// safeNext rejects off-origin targets.
	for _, bad := range []string{"//evil.example", "https://evil.example", "/\\evil"} {
		if safeNext(bad) != "" {
			t.Fatalf("safeNext accepted %q", bad)
		}
	}
	if safeNext("/sso/authorize?x=1") != "/sso/authorize?x=1" {
		t.Fatalf("safeNext rejected a valid relative path")
	}
}
