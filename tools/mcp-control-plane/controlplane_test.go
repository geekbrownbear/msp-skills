package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
		{Email: "a@b.net", Name: "A", Role: RoleSuperAdmin,
			Grants: map[string]CPGrant{"halopsa": {Access: "read"}, "quickbooks": {Access: "none"}, "immybot": {Access: "write"}},
			Tokens: []TokenRef{{Hash: "deadbeef", Label: "laptop"}}},
		{Email: "d@b.net", Name: "D", Role: RoleUser, Disabled: true},
	}
	acts := buildGatewayActors(users)
	if len(acts) != 2 { // disabled excluded; a -> email actor + 1 token actor
		t.Fatalf("want 2 actors, got %d", len(acts))
	}
	base := acts[0]
	if base.Email != "a@b.net" || !base.Admin {
		t.Fatalf("bad base actor %+v", base)
	}
	if g, ok := base.Grants["halopsa"]; !ok || g.Write {
		t.Fatalf("halopsa should be read-only: %+v", base.Grants)
	}
	if g, ok := base.Grants["immybot"]; !ok || !g.Write {
		t.Fatalf("immybot should be write: %+v", base.Grants)
	}
	if _, ok := base.Grants["quickbooks"]; ok {
		t.Fatalf("quickbooks 'none' should be omitted")
	}
	if acts[1].TokenSHA256 != "deadbeef" {
		t.Fatalf("token actor missing hash: %+v", acts[1])
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
