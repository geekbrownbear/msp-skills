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
	a := NewAuthenticator([]Actor{testActor("alice", "secret-token", Grant{})})
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
