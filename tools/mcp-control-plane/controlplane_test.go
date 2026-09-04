package main

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
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
	srv := NewServer(store, NewSessions(time.Hour))
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

// ---- test helpers ----

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
