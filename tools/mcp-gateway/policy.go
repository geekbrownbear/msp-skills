package main

import (
	"fmt"
	"strings"
)

// Decision is the outcome of a policy evaluation.
type Decision struct {
	Allow  bool
	Reason string
	Class  string // read | write | unclassified
}

// Evaluate decides whether an actor may call a tool on a connector.
//
// Three deliberate choices:
//
// Deny wins over allow, so a broad allow plus a targeted deny is safe to write.
//
// An empty allow list means nothing, not everything. Defaulting an unspecified
// permission to full access is how a config typo becomes a breach.
//
// A tool whose class is unknown is treated as a write. The class comes from the
// connector's own readOnlyHint annotation, and #275 documents cases where that
// annotation is wrong, so "we could not tell" must not resolve to "allowed".
func Evaluate(actor *Actor, connector, tool string, readOnly *bool) Decision {
	grant, ok := actor.Grants[connector]
	if !ok {
		return Decision{Reason: fmt.Sprintf("actor %q has no grant for connector %q", actor.Name, connector)}
	}

	class := "unclassified"
	switch {
	case readOnly == nil:
	case *readOnly:
		class = "read"
	default:
		class = "write"
	}

	for _, pat := range grant.DenyTools {
		if matchGlob(pat, tool) {
			return Decision{Reason: fmt.Sprintf("tool %q matches deny pattern %q", tool, pat), Class: class}
		}
	}
	allowed := false
	for _, pat := range grant.AllowTools {
		if matchGlob(pat, tool) {
			allowed = true
			break
		}
	}
	if !allowed {
		return Decision{
			Reason: fmt.Sprintf("tool %q is not in the allow list for connector %q", tool, connector),
			Class:  class,
		}
	}
	if class != "read" && !grant.Write {
		return Decision{
			Reason: fmt.Sprintf(
				"tool %q is %s and this grant is read-only. An unannotated tool counts as a write",
				tool, class),
			Class: class,
		}
	}
	return Decision{Allow: true, Class: class}
}

// matchGlob supports a leading and/or trailing '*' only, which covers
// "everything", "prefix_*", "*_suffix" and exact names. A full glob engine
// would be more expressive and much easier to get subtly wrong in a security
// decision.
func matchGlob(pattern, s string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") && len(pattern) > 2:
		return strings.Contains(s, pattern[1:len(pattern)-1])
	case strings.HasPrefix(pattern, "*"):
		return strings.HasSuffix(s, pattern[1:])
	case strings.HasSuffix(pattern, "*"):
		return strings.HasPrefix(s, pattern[:len(pattern)-1])
	default:
		return pattern == s
	}
}
