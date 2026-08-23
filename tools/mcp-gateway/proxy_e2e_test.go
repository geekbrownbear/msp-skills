package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestGateway wires a gateway in front of a stub connector.
func newTestGateway(t *testing.T, grant Grant) (*httptest.Server, *httptest.Server, string) {
	t.Helper()

	var upstreamAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"search","annotations":{"readOnlyHint":true}},{"name":"purge","annotations":{"readOnlyHint":false}}]}}`))
	}))
	t.Cleanup(upstream.Close)

	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	cfg := &Config{
		Listen: "10.0.0.5:8080", AuditLog: auditPath, ArgumentsMode: "hash",
		Connectors: map[string]Connector{"halopsa": {URL: upstream.URL + "/mcp"}},
		Actors:     []Actor{testActor("alice", "tok", grant)},
	}
	auditor, err := NewAuditor(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { auditor.Close() })
	gw, err := NewGateway(cfg, auditor)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(gw)
	t.Cleanup(front.Close)
	_ = upstreamAuth
	return front, upstream, auditPath
}

func post(t *testing.T, url, token, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestE2EUnauthenticatedIs401(t *testing.T) {
	front, _, _ := newTestGateway(t, Grant{AllowTools: []string{"*"}})
	resp := post(t, front.URL+"/mcp/halopsa", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("401 should carry WWW-Authenticate")
	}
}

func TestE2EUnknownConnectorIs404(t *testing.T) {
	front, _, _ := newTestGateway(t, Grant{AllowTools: []string{"*"}})
	resp := post(t, front.URL+"/mcp/nosuch", "tok", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("want 404, got %d", resp.StatusCode)
	}
}

func TestE2EAllowedCallProxiesAndAudits(t *testing.T) {
	front, _, auditPath := newTestGateway(t, Grant{AllowTools: []string{"*"}})
	// Prime annotations via tools/list, then call the read-only tool.
	post(t, front.URL+"/mcp/halopsa", "tok", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`).Body.Close()
	resp := post(t, front.URL+"/mcp/halopsa", "tok", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search","arguments":{"q":"acme"}}}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	events := readEvents(t, auditPath)
	var found bool
	for _, e := range events {
		if e.MCP.Tool == "search" && e.Policy.Decision == "allow" {
			found = true
			if e.Actor.Name != "alice" {
				t.Fatalf("audit attributed to %q", e.Actor.Name)
			}
			if e.Arguments == nil || e.Arguments.Mode != "hash" || e.Arguments.SHA256 == "" {
				t.Fatalf("arguments not hashed: %+v", e.Arguments)
			}
			if strings.Contains(string(e.Arguments.Value), "acme") {
				t.Fatal("audit leaked the argument value in hash mode")
			}
		}
	}
	if !found {
		t.Fatalf("no allow event for search in %d events", len(events))
	}
}

func TestE2EWriteToolDeniedUnderReadOnlyGrant(t *testing.T) {
	front, _, auditPath := newTestGateway(t, Grant{AllowTools: []string{"*"}})
	post(t, front.URL+"/mcp/halopsa", "tok", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`).Body.Close()
	resp := post(t, front.URL+"/mcp/halopsa", "tok", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"purge","arguments":{}}}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403 for a write tool under a read-only grant, got %d", resp.StatusCode)
	}
	// A denial must be recorded, or the log cannot answer "did anyone try".
	for _, e := range readEvents(t, auditPath) {
		if e.MCP.Tool == "purge" && e.Policy.Decision == "deny" {
			if e.Policy.Reason == "" {
				t.Fatal("denial recorded without a reason")
			}
			return
		}
	}
	t.Fatal("denial was not audited")
}

func TestE2EBatchCannotSmuggleADeniedCall(t *testing.T) {
	front, _, _ := newTestGateway(t, Grant{AllowTools: []string{"*"}})
	post(t, front.URL+"/mcp/halopsa", "tok", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`).Body.Close()
	// One allowed call and one denied call in a single batch.
	body := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search"}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"purge"}}]`
	resp := post(t, front.URL+"/mcp/halopsa", "tok", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a batch containing a denied call must be refused, got %d", resp.StatusCode)
	}
}

func TestE2EUpstreamNeverSeesGatewayToken(t *testing.T) {
	var seen string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	dir := t.TempDir()
	cfg := &Config{Listen: "10.0.0.5:8080", AuditLog: filepath.Join(dir, "a.jsonl"), ArgumentsMode: "hash",
		Connectors: map[string]Connector{"halopsa": {URL: upstream.URL + "/mcp"}},
		Actors:     []Actor{testActor("alice", "tok", Grant{AllowTools: []string{"*"}})}}
	auditor, _ := NewAuditor(cfg.AuditLog)
	defer auditor.Close()
	gw, _ := NewGateway(cfg, auditor)
	front := httptest.NewServer(gw)
	defer front.Close()

	post(t, front.URL+"/mcp/halopsa", "tok", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`).Body.Close()
	if strings.Contains(seen, "tok") {
		t.Fatalf("the connector received the technician's gateway token: %q", seen)
	}
}

func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []Event
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad audit line: %v", err)
		}
		out = append(out, e)
	}
	return out
}
