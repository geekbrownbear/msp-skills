// Copyright 2026 Abhi Saini and contributors. Licensed under Apache-2.0. See LICENSE.

package mcp

import (
	"context"
	"fmt"
	"os"
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// readOnlyEnforced reports whether PP_MCP_READONLY asks this server to refuse
// every tool that is not annotated read-only.
//
// The name is deliberately un-prefixed. An operator running a fleet of these
// servers sets one variable for all of them, the same way PP_MCP_TRANSPORT
// already works.
func readOnlyEnforced() bool {
	v := strings.TrimSpace(os.Getenv("PP_MCP_READONLY"))
	return v != "" && v != "0" && !strings.EqualFold(v, "false")
}

// installReadOnlyGate refuses non-read-only tools when PP_MCP_READONLY is set.
//
// WHY THIS IS NOT PART OF installFreshTenantGate.
//
// The tenant gate exempts any tool whose meta carries pp:tenant-gate =
// "child-cli", because the child CLI owns that tool's one live tenant gate.
// That exemption is correct for tenancy and catastrophic for policy: Cobra
// mirrors are the overwhelming majority of the surface on a
// code-orchestration connector, so a policy middleware that inherited the
// exemption would pass its own tests and enforce nothing on almost every tool
// the server advertises. This gate therefore applies to every registered tool
// without exception, which is the whole point of it being a separate wrapper.
//
// WHY IT REFUSES AT CALL TIME RATHER THAN SKIPPING REGISTRATION.
//
// Hiding a blocked tool from tools/list produces a symptom with no cause: the
// model reports that it has no tool for the job, and nothing is logged on
// either side because nothing was called. Refusing the call instead gives the
// model a reason it can relay to the operator, and gives any audit layer in
// front of the server an event to record.
//
// The annotation is only a hint, so this cannot be the sole control. It moves
// the failure class: with enforcement on, a wrongly-annotated write tool is
// refused rather than quietly performed. See Servosity/msp-skills#275, which
// documents two tools annotated read-only that write, and #282.
func installReadOnlyGate(s *server.MCPServer) {
	if !readOnlyEnforced() {
		return
	}
	s.Use(func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return requireReadOnlyTool(s, next)
	})
}

// selfPolicingTools are tools that enforce read-only internally and must NOT
// be refused wholesale by the blanket gate.
//
// The code-orchestration executor is the case that matters. It is one tool
// name dispatching to every endpoint in the registry, so it cannot carry a
// meaningful readOnlyHint: it is read-only for a GET endpoint id and a write
// for a DELETE one. Refusing it wholesale would make read-only mode remove the
// connector's most useful tool AND leave its own method guard unreachable,
// which is exactly what the first version of this gate did.
var selfPolicingTools = map[string]bool{}

// registerSelfPolicingTool marks a tool as enforcing read-only itself.
func registerSelfPolicingTool(name string) { selfPolicingTools[name] = true }

func requireReadOnlyTool(s *server.MCPServer, next server.ToolHandlerFunc) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		name := request.Params.Name
		if selfPolicingTools[name] {
			// Its own guard decides, per endpoint id.
			return next(ctx, request)
		}
		if toolIsReadOnly(s, name) {
			return next(ctx, request)
		}
		return mcplib.NewToolResultError(fmt.Sprintf(
			"%q is refused: this server runs with PP_MCP_READONLY set, and %q is not annotated read-only. "+
				"To allow writes, restart the server without PP_MCP_READONLY.", name, name)), nil
	}
}

// toolIsReadOnly reports whether a registered tool carries readOnlyHint=true.
//
// Absence is treated as "not read-only". Most generated tools that only read
// do carry the annotation, but coverage is incomplete, so an unannotated tool
// is genuinely unclassified rather than known-safe. Failing closed on an
// unclassified tool is the only choice that makes the mode mean anything; the
// cost is that improving annotation coverage is what widens the read-only
// surface, which is the right incentive.
func toolIsReadOnly(s *server.MCPServer, name string) bool {
	entry := s.GetTool(name)
	if entry == nil {
		return false
	}
	hint := entry.Tool.Annotations.ReadOnlyHint
	return hint != nil && *hint
}
