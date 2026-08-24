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

func TestE2ECallBeforeListSelfPrimes(t *testing.T) {
	// The failure mcp-remote exposed: a fresh gateway session whose FIRST
	// request is a tools/call. The gateway must fetch annotations itself
	// rather than denying a read-only tool as unclassified.
	front, _, _ := newTestGateway(t, Grant{AllowTools: []string{"*"}})
	resp := post(t, front.URL+"/mcp/halopsa", "tok", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search","arguments":{}}}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("read-only tool denied before any tools/list passed through: %d", resp.StatusCode)
	}
}

func TestE2ECallBeforeListStillDeniesWrites(t *testing.T) {
	// Self-priming must not fail open: the write tool stays refused.
	front, _, _ := newTestGateway(t, Grant{AllowTools: []string{"*"}})
	resp := post(t, front.URL+"/mcp/halopsa", "tok", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"purge","arguments":{}}}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write tool must stay denied after self-prime, got %d", resp.StatusCode)
	}
}

func TestE2EAggregateFleetFlow(t *testing.T) {
	front, _, auditPath := newTestGateway(t, Grant{AllowTools: []string{"*"}})

	// initialize on the aggregate endpoint
	resp := post(t, front.URL+"/mcp", "tok", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	sid := resp.Header.Get("Mcp-Session-Id")
	resp.Body.Close()
	if sid == "" {
		t.Fatal("aggregate initialize returned no session")
	}
	call := func(body string) map[string]any {
		req, _ := http.NewRequest(http.MethodPost, front.URL+"/mcp", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Mcp-Session-Id", sid)
		r2, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer r2.Body.Close()
		var out map[string]any
		json.NewDecoder(r2.Body).Decode(&out)
		return out
	}

	// tools/list shows exactly the three meta-tools
	out := call(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := out["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("aggregate advertises %d tools, want 3", len(tools))
	}

	// fleet_connectors lists the granted connector
	out = call(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fleet_connectors","arguments":{}}}`)
	txt := out["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(txt, "halopsa") || !strings.Contains(txt, "read-only") {
		t.Fatalf("fleet_connectors missing grant info: %s", txt)
	}

	// fleet_call on a read tool proxies through
	out = call(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fleet_call","arguments":{"connector":"halopsa","tool":"search","arguments":{"q":"x"}}}}`)
	res := out["result"].(map[string]any)
	if res["isError"] == true {
		t.Fatalf("read tool refused through aggregate: %v", res)
	}

	// fleet_call on a write tool is refused and audited
	out = call(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fleet_call","arguments":{"connector":"purgeless","tool":"purge"}}}`)
	_ = out
	out = call(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"fleet_call","arguments":{"connector":"halopsa","tool":"purge"}}}`)
	res = out["result"].(map[string]any)
	if res["isError"] != true {
		t.Fatal("write tool allowed through aggregate under read-only grant")
	}
	found := false
	for _, e := range readEvents(t, auditPath) {
		if e.MCP.Tool == "purge" && e.Policy.Decision == "deny" {
			found = true
		}
	}
	if !found {
		t.Fatal("aggregate denial not audited")
	}
}
