package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// maxBodyBytes caps how much of a request we buffer to audit it. MCP requests
// are small; a body larger than this is either a mistake or an attempt to make
// the gateway hold a lot of memory per connection.
const maxBodyBytes = 4 << 20

// rpcRequest is the subset of JSON-RPC the gateway needs to make a decision.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

// Gateway routes /mcp/<slug> to the matching connector.
type Gateway struct {
	cfg     *Config
	auth    *Authenticator
	auditor *Auditor
	proxies map[string]*httputil.ReverseProxy

	// annotations caches each connector's tool -> readOnlyHint. Two sources:
	// tools/list responses passing through (free), and a direct fetch from the
	// connector on a cache miss (see ensureAnnotations). The fetch matters:
	// without it, a client whose first request in a fresh gateway session is a
	// tools/call gets its read-only tool denied as unclassified, purely on
	// ordering. Found by driving the gateway through mcp-remote, whose test
	// sequence called before listing.
	annMu       sync.RWMutex
	annotations map[string]map[string]*bool
	annClient   *http.Client
	agg         *aggregator
}

func NewGateway(cfg *Config, auditor *Auditor) (*Gateway, error) {
	g := &Gateway{
		cfg:         cfg,
		auth:        NewAuthenticator(cfg.Actors),
		auditor:     auditor,
		proxies:     map[string]*httputil.ReverseProxy{},
		annotations: map[string]map[string]*bool{},
		annClient:   &http.Client{Timeout: 15 * time.Second},
	}
	g.agg = newAggregator(g)
	for slug, conn := range cfg.Connectors {
		target, err := url.Parse(conn.URL)
		if err != nil {
			return nil, fmt.Errorf("connector %q: %w", slug, err)
		}
		p := httputil.NewSingleHostReverseProxy(target)
		// Without this, streamed SSE responses buffer and the client hangs
		// waiting for a flush that only happens when the transfer ends.
		p.FlushInterval = -1
		base := p.Director
		p.Director = func(r *http.Request) {
			base(r)
			r.URL.Path = target.Path
			// The connector must never see the technician's gateway token.
			r.Header.Del("Authorization")
		}
		p.ModifyResponse = g.captureAnnotations(slug)
		g.proxies[slug] = p
	}
	return g, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// /mcp with no connector is the aggregate fleet endpoint: one server, one
	// token, three meta-tools, discovery on demand.
	if p := strings.TrimRight(r.URL.Path, "/"); p == "/mcp" {
		g.agg.ServeHTTP(w, r)
		return
	}
	slug, ok := connectorFromPath(r.URL.Path)
	if !ok {
		http.Error(w, "not found: expected /mcp/<connector>, or /mcp for the fleet endpoint", http.StatusNotFound)
		return
	}
	if _, known := g.cfg.Connectors[slug]; !known {
		http.Error(w, fmt.Sprintf("unknown connector %q", slug), http.StatusNotFound)
		return
	}

	actor := g.auth.Authenticate(r)
	if actor == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="msp-mcp-gateway"`)
		http.Error(w, "unauthorized: supply a bearer token", http.StatusUnauthorized)
		return
	}

	// GET and DELETE carry no JSON-RPC body: they are the SSE stream and
	// session teardown. Authenticate and authorize the connector, then pass
	// them through without pretending to inspect a tool call.
	if r.Method != http.MethodPost {
		if _, granted := actor.Grants[slug]; !granted {
			g.deny(w, actor, slug, "", Decision{Reason: "no grant for this connector"}, r)
			return
		}
		g.proxies[slug].ServeHTTP(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))

	// A batch is a JSON array. Auditing only the object form would let a
	// caller hide every call inside a one-element batch.
	calls, err := parseCalls(body)
	if err != nil {
		http.Error(w, "malformed JSON-RPC body", http.StatusBadRequest)
		return
	}

	for _, c := range calls {
		if c.Method != "tools/call" {
			continue
		}
		g.ensureAnnotations(slug)
		dec := Evaluate(actor, slug, c.Params.Name, g.readOnlyHint(slug, c.Params.Name))
		if !dec.Allow {
			g.deny(w, actor, slug, c.Params.Name, dec, r)
			return
		}
	}

	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	g.proxies[slug].ServeHTTP(rec, r)
	elapsed := time.Since(start)

	for _, c := range calls {
		ev := &Event{
			Actor:     g.eventActor(actor, r),
			Connector: slug,
			MCP:       EventMCP{Method: c.Method, Tool: c.Params.Name},
			Policy:    EventPolicy{Decision: "allow"},
			Result:    &EventResult{Status: fmt.Sprintf("%d", rec.status), DurationMS: elapsed.Milliseconds()},
		}
		if c.Method == "tools/call" {
			ev.Policy.Class = Evaluate(actor, slug, c.Params.Name, g.readOnlyHint(slug, c.Params.Name)).Class
			ev.Arguments = HashArguments(g.cfg.ArgumentsMode, c.Params.Arguments)
		}
		_ = g.auditor.Append(ev)
	}
}

func (g *Gateway) deny(w http.ResponseWriter, actor *Actor, slug, tool string, dec Decision, r *http.Request) {
	// Denials are audited too. A log that records only what succeeded cannot
	// answer "did anyone try".
	_ = g.auditor.Append(&Event{
		Actor:     g.eventActor(actor, r),
		Connector: slug,
		MCP:       EventMCP{Method: "tools/call", Tool: tool},
		Policy:    EventPolicy{Decision: "deny", Reason: dec.Reason, Class: dec.Class},
	})
	http.Error(w, "forbidden: "+dec.Reason, http.StatusForbidden)
}

func (g *Gateway) eventActor(a *Actor, r *http.Request) EventActor {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return EventActor{Name: a.Name, Kind: a.Kind, SourceIP: host}
}

// captureAnnotations learns tool read-only hints from tools/list responses.
func (g *Gateway) captureAnnotations(slug string) func(*http.Response) error {
	return func(resp *http.Response) error {
		if resp.StatusCode != http.StatusOK {
			return nil
		}
		if !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			return nil
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		resp.Body.Close()
		if err != nil {
			return err
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		var parsed struct {
			Result struct {
				Tools []struct {
					Name        string `json:"name"`
					Annotations struct {
						ReadOnlyHint *bool `json:"readOnlyHint"`
					} `json:"annotations"`
				} `json:"tools"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &parsed) != nil || len(parsed.Result.Tools) == 0 {
			return nil
		}
		m := make(map[string]*bool, len(parsed.Result.Tools))
		for _, t := range parsed.Result.Tools {
			m[t.Name] = t.Annotations.ReadOnlyHint
		}
		g.annMu.Lock()
		g.annotations[slug] = m
		g.annMu.Unlock()
		return nil
	}
}

// ensureAnnotations fetches a connector's tool annotations directly when the
// cache has never been filled for it. The gateway performs its own MCP
// handshake against the connector on the internal network; no client
// credentials are involved, and a failure leaves the cache empty, which keeps
// the deny-unclassified default rather than failing open.
func (g *Gateway) ensureAnnotations(slug string) {
	g.annMu.RLock()
	_, ok := g.annotations[slug]
	g.annMu.RUnlock()
	if ok {
		return
	}
	conn, known := g.cfg.Connectors[slug]
	if !known {
		return
	}

	resp, err := g.mcpPost(conn.URL, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"msp-mcp-gateway","version":"1"}}}`)
	if err != nil {
		return
	}
	session := resp.Header.Get("Mcp-Session-Id")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if r2, err := g.mcpPost(conn.URL, session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err == nil {
		io.Copy(io.Discard, r2.Body)
		r2.Body.Close()
	}

	resp, err = g.mcpPost(conn.URL, session, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return
	}
	var parsed struct {
		Result struct {
			Tools []struct {
				Name        string `json:"name"`
				Annotations struct {
					ReadOnlyHint *bool `json:"readOnlyHint"`
				} `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &parsed) != nil || len(parsed.Result.Tools) == 0 {
		return
	}
	m := make(map[string]*bool, len(parsed.Result.Tools))
	for _, t := range parsed.Result.Tools {
		m[t.Name] = t.Annotations.ReadOnlyHint
	}
	g.annMu.Lock()
	g.annotations[slug] = m
	g.annMu.Unlock()
}

// mcpPost sends one JSON-RPC body to a connector's MCP endpoint on the
// internal network, optionally within a downstream session.
func (g *Gateway) mcpPost(url, session, body string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	return g.annClient.Do(req)
}

// hasTool reports whether the connector's cached tool list contains the tool.
// False when the cache is empty, which the caller treats as absent.
func (g *Gateway) hasTool(slug, tool string) bool {
	g.annMu.RLock()
	defer g.annMu.RUnlock()
	m, ok := g.annotations[slug]
	if !ok {
		return false
	}
	_, ok = m[tool]
	return ok
}

func (g *Gateway) readOnlyHint(slug, tool string) *bool {
	g.annMu.RLock()
	defer g.annMu.RUnlock()
	if m, ok := g.annotations[slug]; ok {
		return m[tool]
	}
	return nil
}

func connectorFromPath(p string) (string, bool) {
	p = strings.TrimPrefix(p, "/")
	head, rest, _ := strings.Cut(p, "/")
	if head != "mcp" || rest == "" {
		return "", false
	}
	slug, _, _ := strings.Cut(rest, "/")
	return slug, slug != ""
}

func parseCalls(body []byte) ([]rpcRequest, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var batch []rpcRequest
		if err := json.Unmarshal(trimmed, &batch); err != nil {
			return nil, err
		}
		return batch, nil
	}
	var one rpcRequest
	if err := json.Unmarshal(trimmed, &one); err != nil {
		return nil, err
	}
	return []rpcRequest{one}, nil
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wrote {
		s.status = code
		s.wrote = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
