package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tokenDigest(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

func testActor(name, tok string, g Grant) Actor {
	return Actor{Name: name, Kind: "human", TokenSHA256: tokenDigest(tok), Grants: map[string]Grant{"halopsa": g}}
}

func TestAuthenticate(t *testing.T) {
	a := NewAuthenticator([]Actor{testActor("alice", "secret-token", Grant{})}, nil)
	cases := []struct {
		name, header string
		want         string
	}{
		{"valid", "Bearer secret-token", "alice"},
		{"case-insensitive scheme", "bearer secret-token", "alice"},
		{"wrong token", "Bearer nope", ""},
		{"no header", "", ""},
		{"wrong scheme", "Basic secret-token", ""},
		{"token as scheme", "secret-token", ""},
		{"empty bearer", "Bearer ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/mcp/halopsa", nil)
			if c.header != "" {
				r.Header.Set("Authorization", c.header)
			}
			got := a.Authenticate(r)
			switch {
			case c.want == "" && got != nil:
				t.Fatalf("expected no actor, got %q", got.Name)
			case c.want != "" && got == nil:
				t.Fatalf("expected %q, got none", c.want)
			case c.want != "" && got.Name != c.want:
				t.Fatalf("expected %q, got %q", c.want, got.Name)
			}
		})
	}
}

func TestAuthenticateProxyHeader(t *testing.T) {
	const secret = "proxy-shared-secret"
	proxy := &ProxyAuth{SharedSecretSHA256: tokenDigest(secret)}
	alice := Actor{Name: "alice", Kind: "human", Email: "alice@bearium.net", Grants: map[string]Grant{"halopsa": {}}}
	a := NewAuthenticator([]Actor{alice}, proxy)

	set := func(r *http.Request, secretVal, email string) {
		if secretVal != "" {
			r.Header.Set("X-Gateway-Proxy-Secret", secretVal)
		}
		if email != "" {
			r.Header.Set("X-Forwarded-Email", email)
		}
	}
	cases := []struct {
		name, secretVal, email, want string
	}{
		{"valid identity", secret, "alice@bearium.net", "alice"},
		{"email case-folded", secret, "Alice@Bearium.net", "alice"},
		{"wrong secret", "nope", "alice@bearium.net", ""},
		{"missing secret", "", "alice@bearium.net", ""},
		{"missing email", secret, "", ""},
		{"unknown email", secret, "mallory@evil.test", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/mcp/halopsa", nil)
			set(r, c.secretVal, c.email)
			got := a.Authenticate(r)
			switch {
			case c.want == "" && got != nil:
				t.Fatalf("expected no actor, got %q", got.Name)
			case c.want != "" && (got == nil || got.Name != c.want):
				t.Fatalf("expected %q, got %v", c.want, got)
			}
		})
	}

	// A forged identity header must be ignored entirely when no proxy is
	// configured, so a direct client cannot assert its own email.
	noProxy := NewAuthenticator([]Actor{alice}, nil)
	r := httptest.NewRequest(http.MethodPost, "/mcp/halopsa", nil)
	set(r, secret, "alice@bearium.net")
	if got := noProxy.Authenticate(r); got != nil {
		t.Fatalf("proxy disabled: expected no actor, got %q", got.Name)
	}

	// A bearer token still authenticates a machine actor even with proxy on.
	bob := testActor("bob", "bob-token", Grant{})
	withBoth := NewAuthenticator([]Actor{alice, bob}, proxy)
	rb := httptest.NewRequest(http.MethodPost, "/mcp/halopsa", nil)
	rb.Header.Set("Authorization", "Bearer bob-token")
	if got := withBoth.Authenticate(rb); got == nil || got.Name != "bob" {
		t.Fatalf("expected bob via token, got %v", got)
	}
}

func TestPolicy(t *testing.T) {
	ro, rw := true, false
	cases := []struct {
		name      string
		grant     Grant
		tool      string
		readOnly  *bool
		wantAllow bool
	}{
		{"read tool, read grant", Grant{AllowTools: []string{"*"}}, "search", &ro, true},
		{"write tool, read grant", Grant{AllowTools: []string{"*"}}, "delete", &rw, false},
		{"write tool, write grant", Grant{AllowTools: []string{"*"}, Write: true}, "delete", &rw, true},
		{"unannotated counts as write", Grant{AllowTools: []string{"*"}}, "mystery", nil, false},
		{"unannotated allowed with write grant", Grant{AllowTools: []string{"*"}, Write: true}, "mystery", nil, true},
		{"empty allow list denies", Grant{}, "search", &ro, false},
		{"deny beats allow", Grant{AllowTools: []string{"*"}, DenyTools: []string{"halopsa_execute"}}, "halopsa_execute", &ro, false},
		{"prefix glob", Grant{AllowTools: []string{"tickets_*"}}, "tickets_get", &ro, true},
		{"prefix glob misses", Grant{AllowTools: []string{"tickets_*"}}, "assets_get", &ro, false},
		{"suffix glob", Grant{AllowTools: []string{"*_get"}}, "assets_get", &ro, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := testActor("alice", "t", c.grant)
			got := Evaluate(&a, "halopsa", c.tool, c.readOnly)
			if got.Allow != c.wantAllow {
				t.Fatalf("allow=%v want %v (reason %q)", got.Allow, c.wantAllow, got.Reason)
			}
			if !got.Allow && got.Reason == "" {
				t.Fatal("a denial must carry a reason")
			}
		})
	}
}

func TestPolicyUngrantedConnectorDenied(t *testing.T) {
	a := testActor("alice", "t", Grant{AllowTools: []string{"*"}})
	ro := true
	if d := Evaluate(&a, "cipp", "search", &ro); d.Allow {
		t.Fatal("actor with no grant for cipp was allowed")
	}
}

func TestAuditChainDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	au, err := NewAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := au.Append(&Event{Connector: "halopsa", MCP: EventMCP{Method: "tools/call", Tool: "search"}}); err != nil {
			t.Fatal(err)
		}
	}
	au.Close()

	if err := VerifyChain(path, io_Discard{}); err != nil {
		t.Fatalf("fresh chain should verify: %v", err)
	}

	// Edit one line in the middle.
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	lines[2] = strings.Replace(lines[2], `"search"`, `"innocent"`, 1)
	os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	err = VerifyChain(path, io_Discard{})
	if err == nil {
		t.Fatal("edited log verified clean")
	}
	if !strings.Contains(err.Error(), "chain broken") {
		t.Fatalf("expected a chain break, got: %v", err)
	}
}

func TestAuditChainDetectsDeletion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	au, _ := NewAuditor(path)
	for i := 0; i < 4; i++ {
		au.Append(&Event{Connector: "halopsa"})
	}
	au.Close()

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// Remove the second event, the classic "hide what I did" edit.
	kept := append([]string{lines[0]}, lines[2:]...)
	os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600)

	if err := VerifyChain(path, io_Discard{}); err == nil {
		t.Fatal("log with a deleted line verified clean")
	}
}

func TestAuditChainSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	au, _ := NewAuditor(path)
	au.Append(&Event{Connector: "halopsa"})
	au.Append(&Event{Connector: "halopsa"})
	au.Close()

	// Reopening must continue the chain, not restart it.
	au2, err := NewAuditor(path)
	if err != nil {
		t.Fatal(err)
	}
	au2.Append(&Event{Connector: "halopsa"})
	au2.Close()

	if err := VerifyChain(path, io_Discard{}); err != nil {
		t.Fatalf("chain broken across restart: %v", err)
	}
}

func TestArgumentsModeDefaultsToHash(t *testing.T) {
	raw := json.RawMessage(`{"email":"customer@example.com"}`)
	got := HashArguments("", raw)
	if got.Mode != "hash" || got.SHA256 == "" {
		t.Fatalf("default mode should hash, got %+v", got)
	}
	if strings.Contains(string(got.Value), "customer@example.com") {
		t.Fatal("hash mode leaked the argument value")
	}
	if full := HashArguments("full", raw); !strings.Contains(string(full.Value), "customer@example.com") {
		t.Fatal("full mode should retain the value")
	}
	if none := HashArguments("none", raw); none.SHA256 != "" || none.Value != nil {
		t.Fatal("none mode should retain nothing")
	}
}

func TestConfigRejectsWildcardBind(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8080", ":8080", "[::]:8080"} {
		c := Config{Listen: listen, AuditLog: "/tmp/a.jsonl",
			Connectors: map[string]Connector{"halopsa": {URL: "http://halopsa:7777/mcp"}},
			Actors:     []Actor{testActor("alice", "t", Grant{})}}
		if err := c.validate(); err == nil {
			t.Fatalf("listen %q should be rejected", listen)
		}
	}
}

func TestConfigRejectsSharedToken(t *testing.T) {
	c := Config{Listen: "10.0.0.5:8080", AuditLog: "/tmp/a.jsonl",
		Connectors: map[string]Connector{"halopsa": {URL: "http://halopsa:7777/mcp"}},
		Actors: []Actor{
			testActor("alice", "same", Grant{}),
			testActor("bob", "same", Grant{}),
		}}
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "share a token") {
		t.Fatalf("shared tokens should be rejected, got %v", err)
	}
}

func TestParseCallsHandlesBatch(t *testing.T) {
	batch := []byte(`[{"jsonrpc":"2.0","method":"tools/call","params":{"name":"a"}},{"jsonrpc":"2.0","method":"tools/call","params":{"name":"b"}}]`)
	calls, err := parseCalls(batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[1].Params.Name != "b" {
		t.Fatalf("batch not parsed: %+v", calls)
	}
}

func TestConnectorFromPath(t *testing.T) {
	cases := map[string]string{
		"/mcp/halopsa":       "halopsa",
		"/mcp/halopsa/":      "halopsa",
		"/mcp/halopsa/extra": "halopsa",
		"/mcp":               "",
		"/":                  "",
		"/other/halopsa":     "",
	}
	for path, want := range cases {
		got, ok := connectorFromPath(path)
		if want == "" && ok {
			t.Fatalf("%s: expected no match, got %q", path, got)
		}
		if want != "" && got != want {
			t.Fatalf("%s: got %q want %q", path, got, want)
		}
	}
}

type io_Discard struct{}

func (io_Discard) Write(p []byte) (int, error) { return len(p), nil }

func TestConfigWildcardBindAllowedWithExplicitOptIn(t *testing.T) {
	t.Setenv("MSP_GATEWAY_ALLOW_WILDCARD_BIND", "1")
	c := Config{Listen: "0.0.0.0:8080", AuditLog: "/tmp/a.jsonl",
		Connectors: map[string]Connector{"halopsa": {URL: "http://halopsa:7777/mcp"}},
		Actors:     []Actor{testActor("alice", "t", Grant{})}}
	if err := c.validate(); err != nil {
		t.Fatalf("opt-in should permit a wildcard bind: %v", err)
	}
}

func TestMetaToolSchemasAreClientValid(t *testing.T) {
	// Claude Desktop validates inputSchema.required as array-or-absent; a
	// JSON null there makes it refuse the entire tools/list.
	raw, err := json.Marshal(metaTools())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"required":null`) {
		t.Fatalf("a meta-tool schema serializes required as null: %s", raw)
	}
	var tools []struct {
		InputSchema struct {
			Type     string   `json:"type"`
			Required []string `json:"required"`
		} `json:"inputSchema"`
	}
	if err := json.Unmarshal(raw, &tools); err != nil {
		t.Fatalf("meta-tool schemas do not round-trip: %v", err)
	}
	if len(tools) != 4 {
		t.Fatalf("expected 4 meta-tools, got %d", len(tools))
	}
}
