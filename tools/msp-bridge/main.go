// msp-bridge connects a stdio MCP client (Claude Desktop) to the fleet
// gateway's streamable HTTP endpoint with a bearer token.
//
// It exists because the usual bridge, mcp-remote, dragged three Windows
// failure modes into what should be plumbing: cmd.exe quoting of
// "Program Files", npx cold-starts, and a localhost OAuth-callback listener
// that Windows' excluded port ranges refuse to bind. This program has no
// package manager, no shell, and no listener: stdin lines become POSTs,
// response bodies become stdout lines, and that is all.
//
// Usage: msp-bridge <gateway-url>
// The token comes from MSP_BRIDGE_TOKEN (preferred, keeps it out of process
// argument lists) or --token.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	token := flag.String("token", "", "bearer token (or set MSP_BRIDGE_TOKEN)")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: msp-bridge <gateway-url>")
		os.Exit(2)
	}
	url := flag.Arg(0)
	if *token == "" {
		*token = strings.TrimSpace(os.Getenv("MSP_BRIDGE_TOKEN"))
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "msp-bridge: no token; set MSP_BRIDGE_TOKEN or pass --token")
		os.Exit(2)
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	out := bufio.NewWriter(os.Stdout)
	var session string

	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 32*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(line))
		if err != nil {
			fmt.Fprintf(os.Stderr, "msp-bridge: building request: %v\n", err)
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+*token)
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		resp, err := client.Do(req)
		if err != nil {
			emit(out, errorFor(line, fmt.Sprintf("gateway unreachable: %v", err)))
			continue
		}
		if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
			session = sid
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()

		switch {
		case resp.StatusCode == http.StatusAccepted || len(bytes.TrimSpace(body)) == 0:
			// notification acknowledged; nothing to say
		case resp.StatusCode >= 400:
			emit(out, errorFor(line, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, firstLine(body))))
		case strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream"):
			for _, payload := range sseData(body) {
				emit(out, payload)
			}
		default:
			emit(out, body)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "msp-bridge: stdin: %v\n", err)
		os.Exit(1)
	}
}

// emit writes one JSON value as exactly one line, whatever whitespace the
// server used.
func emit(out *bufio.Writer, raw []byte) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		fmt.Fprintf(os.Stderr, "msp-bridge: non-JSON response dropped: %.120s\n", raw)
		return
	}
	compact.WriteByte('\n')
	out.Write(compact.Bytes())
	out.Flush()
}

// errorFor builds a JSON-RPC error response carrying the request's id, so the
// client fails the one call instead of wedging the session.
func errorFor(request []byte, msg string) []byte {
	var probe struct {
		ID json.RawMessage `json:"id"`
	}
	json.Unmarshal(request, &probe)
	if len(probe.ID) == 0 {
		probe.ID = json.RawMessage("null")
	}
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": probe.ID,
		"error": map[string]any{"code": -32000, "message": msg},
	})
	return b
}

// sseData extracts the data payloads from an SSE body. The gateway answers
// plain JSON today; this keeps the bridge correct if a server ever streams.
func sseData(body []byte) [][]byte {
	var out [][]byte
	for _, ln := range bytes.Split(body, []byte("\n")) {
		ln = bytes.TrimRight(ln, "\r")
		if rest, ok := bytes.CutPrefix(ln, []byte("data:")); ok {
			out = append(out, bytes.TrimSpace(rest))
		}
	}
	return out
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
