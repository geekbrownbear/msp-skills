// The aggregate endpoint: one MCP server at /mcp that fronts the whole fleet.
//
// A Desktop or Code client configures ONE server with ONE token. Instead of
// flattening every connector's tools into one enormous list (the fleet
// advertises ~500 across 14 connectors, which would bloat every conversation),
// the aggregate exposes three meta-tools and lets the model discover on
// demand, the same shape Anthropic's own deferred-tool pattern uses:
//
//   fleet_connectors           what this token can reach
//   fleet_tools(connector)     a connector's tools, schemas and annotations
//   fleet_call(connector,tool) invoke one, under exactly the same policy and
//                              audit as the per-connector paths
//
// Enforcement is identical to /mcp/<slug>: same Evaluate, same audit events,
// same deny-unclassified default. The per-connector paths remain for clients
// that want a curated single-connector surface.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type aggSession struct {
	actor      *Actor
	downstream map[string]string // slug -> downstream Mcp-Session-Id
	mu         sync.Mutex
}

type aggregator struct {
	g        *Gateway
	mu       sync.Mutex
	sessions map[string]*aggSession
}

func newAggregator(g *Gateway) *aggregator {
	return &aggregator{g: g, sessions: map[string]*aggSession{}}
}

func rpcError(id json.RawMessage, code int, msg string) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}}
}

func rpcResult(id json.RawMessage, result any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
}

func toolText(v any) map[string]any {
	b, _ := json.MarshalIndent(v, "", " ")
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}}
}

func toolErr(msg string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": msg}}, "isError": true}
}

// ServeHTTP handles the aggregate MCP server at /mcp.
func (a *aggregator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	actor := a.g.auth.Load().Authenticate(r)
	if actor == nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="msp-mcp-gateway"`)
		http.Error(w, "unauthorized: supply a bearer token", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
	case http.MethodGet:
		// No server-initiated stream; the spec allows refusing it.
		http.Error(w, "no event stream", http.StatusMethodNotAllowed)
		return
	case http.MethodDelete:
		a.mu.Lock()
		delete(a.sessions, r.Header.Get("Mcp-Session-Id"))
		a.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		return
	default:
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "reading body", http.StatusBadRequest)
		return
	}
	var req rpcRequest
	if err := json.Unmarshal(bytes.TrimSpace(body), &req); err != nil {
		http.Error(w, "malformed JSON-RPC", http.StatusBadRequest)
		return
	}

	// Notifications get a 202 and no body.
	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		sid := a.newSession(actor)
		w.Header().Set("Mcp-Session-Id", sid)
		writeJSON(w, rpcResult(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "MSP Fleet", "version": "1"},
		}))
	case "tools/list":
		writeJSON(w, rpcResult(req.ID, map[string]any{"tools": metaTools()}))
	case "tools/call":
		sess := a.session(r.Header.Get("Mcp-Session-Id"))
		if sess == nil {
			http.Error(w, "Invalid session ID", http.StatusNotFound)
			return
		}
		writeJSON(w, rpcResult(req.ID, a.dispatch(sess, actor, req, r)))
	case "ping":
		writeJSON(w, rpcResult(req.ID, map[string]any{}))
	default:
		writeJSON(w, rpcError(req.ID, -32601, "method not supported on the aggregate endpoint: "+req.Method))
	}
}

func (a *aggregator) newSession(actor *Actor) string {
	b := make([]byte, 16)
	rand.Read(b)
	sid := "fleet-" + hex.EncodeToString(b)
	a.mu.Lock()
	a.sessions[sid] = &aggSession{actor: actor, downstream: map[string]string{}}
	a.mu.Unlock()
	return sid
}

func (a *aggregator) session(sid string) *aggSession {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessions[sid]
}

func (a *aggregator) dispatch(sess *aggSession, actor *Actor, req rpcRequest, r *http.Request) map[string]any {
	var args struct {
		Connector string          `json:"connector"`
		Tool      string          `json:"tool"`
		Arguments json.RawMessage `json:"arguments"`
	}
	json.Unmarshal(req.Params.Arguments, &args)

	switch req.Params.Name {
	case "fleet_overview":
		return a.overview(sess, actor, r)

	case "fleet_connectors":
		type row struct {
			Slug   string `json:"connector"`
			Vendor string `json:"grant"`
		}
		var rows []row
		for slug := range a.g.cfg.Connectors {
			if grant, ok := actor.Grants[slug]; ok {
				mode := "read-only"
				if grant.Write {
					mode = "read-write"
				}
				rows = append(rows, row{Slug: slug, Vendor: mode})
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Slug < rows[j].Slug })
		return toolText(map[string]any{
			"connectors": rows,
			"next":       "fleet_overview surveys every mirror in one call; fleet_tools lists one connector; fleet_call invokes a tool",
		})

	case "fleet_tools":
		if _, ok := actor.Grants[args.Connector]; !ok {
			return toolErr(fmt.Sprintf("no grant for connector %q", args.Connector))
		}
		raw, err := a.downstreamToolsList(sess, args.Connector)
		if err != nil {
			return toolErr(fmt.Sprintf("listing %s tools: %v", args.Connector, err))
		}
		return map[string]any{"content": []map[string]any{{"type": "text", "text": string(raw)}}}

	case "fleet_call":
		if args.Connector == "" || args.Tool == "" {
			return toolErr("fleet_call needs connector and tool")
		}
		a.g.ensureAnnotations(args.Connector)
		dec := Evaluate(actor, args.Connector, args.Tool, a.g.readOnlyHint(args.Connector, args.Tool))
		ev := &Event{
			Actor:     a.g.eventActor(actor, r),
			Connector: args.Connector,
			MCP:       EventMCP{Method: "tools/call", Tool: args.Tool},
		}
		if !dec.Allow {
			ev.Policy = EventPolicy{Decision: "deny", Reason: dec.Reason, Class: dec.Class}
			a.g.auditor.Append(ev)
			return toolErr("forbidden: " + dec.Reason)
		}
		start := time.Now()
		raw, err := a.downstreamCall(sess, args.Connector, args.Tool, args.Arguments)
		ev.Policy = EventPolicy{Decision: "allow", Class: dec.Class}
		ev.Arguments = HashArguments(a.g.cfg.ArgumentsMode, args.Arguments)
		status := "ok"
		if err != nil {
			status = "error"
		}
		ev.Result = &EventResult{Status: status, DurationMS: time.Since(start).Milliseconds()}
		a.g.auditor.Append(ev)
		if err != nil {
			return toolErr(fmt.Sprintf("calling %s.%s: %v", args.Connector, args.Tool, err))
		}
		return map[string]any{"content": []map[string]any{{"type": "text", "text": string(raw)}}}

	default:
		return toolErr("unknown tool " + req.Params.Name)
	}
}

// overview surveys every granted connector's mirror in one tool call, by
// invoking each connector's standard `analytics` summary concurrently.
//
// It exists because the discovery flow, correct as it is, spends a client
// tool call per step: a "look at everything" request across 14 connectors
// burned a Desktop conversation's whole tool budget on plumbing before any
// real question got asked. One overview call buys the model the map, so the
// budget goes to the follow-ups that matter. Every downstream call is policy
// checked and audited exactly as if the client had made it itself.
func (a *aggregator) overview(sess *aggSession, actor *Actor, r *http.Request) map[string]any {
	type row struct {
		slug string
		out  map[string]any
	}
	var slugs []string
	for slug := range a.g.cfg.Connectors {
		if _, ok := actor.Grants[slug]; ok {
			slugs = append(slugs, slug)
		}
	}
	sort.Strings(slugs)

	rows := make(chan row, len(slugs))
	sem := make(chan struct{}, 6)
	for _, slug := range slugs {
		go func(slug string) {
			sem <- struct{}{}
			defer func() { <-sem }()
			rows <- row{slug, a.overviewOne(sess, actor, slug, r)}
		}(slug)
	}
	result := map[string]any{}
	for range slugs {
		rw := <-rows
		result[rw.slug] = rw.out
	}
	return toolText(map[string]any{
		"mirror_summaries": result,
		"note":             "counts are the local mirror per connector; a thin or empty entry means little is synced there, not that the connector is down. Use fleet_tools + fleet_call for live reads and deep dives.",
	})
}

func (a *aggregator) overviewOne(sess *aggSession, actor *Actor, slug string, r *http.Request) map[string]any {
	a.g.ensureAnnotations(slug)
	// Not every connector ships the standard summary tool (quickbooks does
	// not); absent means "nothing to survey", not a policy violation.
	if !a.g.hasTool(slug, "analytics") {
		return map[string]any{"mirror": "no analytics summary tool; use fleet_tools to see what it offers"}
	}
	dec := Evaluate(actor, slug, "analytics", a.g.readOnlyHint(slug, "analytics"))
	ev := &Event{
		Actor:     a.g.eventActor(actor, r),
		Connector: slug,
		MCP:       EventMCP{Method: "tools/call", Tool: "analytics"},
	}
	if !dec.Allow {
		ev.Policy = EventPolicy{Decision: "deny", Reason: dec.Reason, Class: dec.Class}
		a.g.auditor.Append(ev)
		return map[string]any{"error": "analytics not permitted: " + dec.Reason}
	}
	start := time.Now()
	raw, err := a.downstreamCall(sess, slug, "analytics", json.RawMessage(`{}`))
	ev.Policy = EventPolicy{Decision: "allow", Class: dec.Class}
	status := "ok"
	if err != nil {
		status = "error"
	}
	ev.Result = &EventResult{Status: status, DurationMS: time.Since(start).Milliseconds()}
	a.g.auditor.Append(ev)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}

	// analytics prints a "Resource Type	Count" table; turn it into numbers.
	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	counts := map[string]int64{}
	if json.Unmarshal(raw, &parsed) == nil {
		for _, c := range parsed.Content {
			if c.Type != "text" {
				continue
			}
			for _, ln := range strings.Split(c.Text, "\n") {
				name, num, ok := strings.Cut(ln, "\t")
				if !ok {
					continue
				}
				var n int64
				if _, err := fmt.Sscanf(strings.TrimSpace(num), "%d", &n); err == nil && name != "" {
					counts[strings.TrimSpace(name)] = n
					if len(counts) >= 60 {
						break
					}
				}
			}
		}
	}
	if len(counts) == 0 {
		return map[string]any{"mirror": "empty or unparsed"}
	}
	return map[string]any{"resources": counts}
}

func metaTools() []map[string]any {
	obj := func(props map[string]any, required ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		// An empty variadic is a nil slice, which encoding/json renders as
		// null, and clients validate required as array-or-absent. Claude
		// Desktop refused the whole tools/list over exactly this.
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	ro, notRo := true, false
	return []map[string]any{
		{
			"name":        "fleet_overview",
			"description": "One-call survey of the whole fleet: every connector's local mirror summarized as resource counts. Start here for any broad question; it costs one tool call instead of one per connector.",
			"inputSchema": obj(map[string]any{}),
			"annotations": map[string]any{"readOnlyHint": &ro},
		},
		{
			"name":        "fleet_connectors",
			"description": "List the MSP connectors this token can reach (HaloPSA, ImmyBot, CIPP, Hudu, ThreatLocker, and the rest of the fleet) and whether each grant is read-only. Start here.",
			"inputSchema": obj(map[string]any{}),
			"annotations": map[string]any{"readOnlyHint": &ro},
		},
		{
			"name":        "fleet_tools",
			"description": "List one connector's tools with their schemas and annotations. Call before using an unfamiliar connector.",
			"inputSchema": obj(map[string]any{"connector": str("connector name from fleet_connectors")}, "connector"),
			"annotations": map[string]any{"readOnlyHint": &ro},
		},
		{
			"name":        "fleet_call",
			"description": "Invoke one tool on one connector, e.g. connector=immybot tool=analytics. Policy applies: read-only grants refuse tools that are not provably reads.",
			"inputSchema": obj(map[string]any{
				"connector": str("connector name"),
				"tool":      str("tool name from fleet_tools"),
				"arguments": map[string]any{"type": "object", "description": "arguments for the tool"},
			}, "connector", "tool"),
			"annotations": map[string]any{"readOnlyHint": &notRo, "openWorldHint": &ro},
		},
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// --- downstream plumbing: one MCP session per (aggregate session, connector) ---

func (a *aggregator) downstreamSession(sess *aggSession, slug string) (string, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sid, ok := sess.downstream[slug]; ok {
		return sid, nil
	}
	conn, ok := a.g.cfg.Connectors[slug]
	if !ok {
		return "", fmt.Errorf("unknown connector")
	}
	resp, err := a.g.mcpPost(conn.URL, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"msp-mcp-gateway","version":"1"}}}`)
	if err != nil {
		return "", err
	}
	sid := resp.Header.Get("Mcp-Session-Id")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if r2, err := a.g.mcpPost(conn.URL, sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err == nil {
		io.Copy(io.Discard, r2.Body)
		r2.Body.Close()
	}
	sess.downstream[slug] = sid
	return sid, nil
}

func (a *aggregator) roundTrip(sess *aggSession, slug, body string) (json.RawMessage, error) {
	sid, err := a.downstreamSession(sess, slug)
	if err != nil {
		return nil, err
	}
	conn := a.g.cfg.Connectors[slug]
	resp, err := a.g.mcpPost(conn.URL, sid, body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		// downstream session expired (connector restarted); mint a fresh one once
		sess.mu.Lock()
		delete(sess.downstream, slug)
		sess.mu.Unlock()
		sid, err = a.downstreamSession(sess, slug)
		if err != nil {
			return nil, err
		}
		resp2, err := a.g.mcpPost(conn.URL, sid, body)
		if err != nil {
			return nil, err
		}
		defer resp2.Body.Close()
		return io.ReadAll(io.LimitReader(resp2.Body, maxBodyBytes))
	}
	return raw, nil
}

func (a *aggregator) downstreamToolsList(sess *aggSession, slug string) (json.RawMessage, error) {
	raw, err := a.roundTrip(sess, slug, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(raw, &parsed) == nil && len(parsed.Result) > 0 {
		return parsed.Result, nil
	}
	return raw, nil
}

func (a *aggregator) downstreamCall(sess *aggSession, slug, tool string, args json.RawMessage) (json.RawMessage, error) {
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	call, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args},
	})
	raw, err := a.roundTrip(sess, slug, string(call))
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &parsed) == nil {
		if parsed.Error != nil {
			return nil, fmt.Errorf("%s", parsed.Error.Message)
		}
		if len(parsed.Result) > 0 {
			return parsed.Result, nil
		}
	}
	return raw, nil
}
