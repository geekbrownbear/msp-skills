// Read-only enforcement for the MCP surface. Hand-written; see
// skills/immybot/handfixes.json entry "mcp-readonly-enforcement".

package mcp

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// readOnlyEnvVar switches the server into a mode where it refuses to perform
// writes rather than merely annotating which tools perform them.
const readOnlyEnvVar = "PP_MCP_READONLY"

// readOnlyEnforced reports whether the operator asked for enforcement.
// mcp:read-only is a hint that hosts read to decide what to auto-approve;
// nothing acts on it. This makes it load-bearing.
func readOnlyEnforced() bool {
	v := strings.TrimSpace(os.Getenv(readOnlyEnvVar))
	return v != "" && v != "0" && !strings.EqualFold(v, "false")
}

var (
	selfPolicingMu    sync.RWMutex
	selfPolicingTools = map[string]bool{}
)

// registerSelfPolicingTool records a tool that enforces read-only itself, at a
// finer granularity than the tool name can express.
//
// Without this exemption the blanket gate below refuses immybot_execute
// outright, which removes the connector's most useful tool AND makes the
// per-endpoint method check in code_orch.go unreachable. That is not a
// hypothetical: the first version of this file did exactly that, it passed its
// own tests, and a live handshake was what caught it.
func registerSelfPolicingTool(name string) {
	selfPolicingMu.Lock()
	defer selfPolicingMu.Unlock()
	selfPolicingTools[name] = true
}

func isSelfPolicing(name string) bool {
	selfPolicingMu.RLock()
	defer selfPolicingMu.RUnlock()
	return selfPolicingTools[name]
}

// toolIsReadOnly reports whether the registered tool claims to be read-only.
// An absent annotation is treated as a write: the annotation is what the tool
// asserts about itself, and a tool that asserts nothing has not earned the
// benefit of the doubt in a mode whose entire purpose is refusing writes.
func toolIsReadOnly(s *server.MCPServer, name string) bool {
	entry := s.GetTool(name)
	if entry == nil {
		return false
	}
	hint := entry.Tool.Annotations.ReadOnlyHint
	return hint != nil && *hint
}

// installReadOnlyGate refuses any call that is not provably a read.
//
// This is deliberately a SEPARATE middleware from installFreshTenantGate rather
// than a branch inside it. The tenant gate exempts every tool carrying
// pp:tenant-gate = "child-cli", which is every Cobra mirror and so the
// overwhelming majority of the advertised surface. A policy middleware that
// inherited that exemption would enforce nothing on almost everything while
// still passing its own tests. See Servosity/msp-skills#282.
func installReadOnlyGate(s *server.MCPServer) {
	if !readOnlyEnforced() {
		return
	}
	s.Use(func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			name := request.Params.Name
			// Tools that police themselves decide per call; the blanket
			// verdict here is too coarse for them.
			if isSelfPolicing(name) {
				return next(ctx, request)
			}
			if toolIsReadOnly(s, name) {
				return next(ctx, request)
			}
			return mcplib.NewToolResultError(fmt.Sprintf(
				"tool %q is not annotated read-only, and this server runs with %s set; "+
					"unset %s to allow writes",
				name, readOnlyEnvVar, readOnlyEnvVar)), nil
		}
	})
}
