// Configuration for the MSP MCP gateway. Standard library only: any new
// dependency here is a P1 in check_security_gate.py, and this process holds
// every technician's access to every vendor.

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Config is the whole gateway configuration, loaded once at startup.
type Config struct {
	// Listen is host:port. A bare port or 0.0.0.0 is rejected: Docker's
	// published ports DNAT ahead of ufw and firewalld, so binding a wildcard
	// here can expose the gateway on interfaces the operator believes are
	// firewalled.
	Listen string `json:"listen"`

	// AuditLog is the append-only hash-chained event log.
	AuditLog string `json:"audit_log"`

	// ArgumentsMode is none | hash | full, default hash. Tool arguments
	// routinely carry customer names, ticket bodies and mailbox addresses, so
	// an audit log recording them verbatim is itself a PII store.
	ArgumentsMode string `json:"arguments_mode"`

	Connectors map[string]Connector `json:"connectors"`
	Actors     []Actor              `json:"actors"`

	// ProxyAuth, when set, lets a trusted SSO proxy (oauth2-proxy/Authentik in
	// front) assert the authenticated user's identity via a header. Requests
	// carrying identity headers are only honored when they also carry the
	// shared secret, so an internal network peer cannot forge an identity.
	ProxyAuth *ProxyAuth `json:"proxy_auth,omitempty"`
}

type ProxyAuth struct {
	// SharedSecretSHA256 is the hex sha256 of a secret the trusted proxy sends
	// in TrustHeader on every request. The plaintext is never stored here.
	SharedSecretSHA256 string `json:"shared_secret_sha256"`

	// TrustHeader carries the shared secret. Default: X-Gateway-Proxy-Secret.
	TrustHeader string `json:"trust_header,omitempty"`

	// EmailHeader carries the authenticated user's email. Default:
	// X-Forwarded-Email (what oauth2-proxy sets with --set-xauthrequest).
	EmailHeader string `json:"email_header,omitempty"`
}

func (p *ProxyAuth) trustHeader() string {
	if p.TrustHeader != "" {
		return p.TrustHeader
	}
	return "X-Gateway-Proxy-Secret"
}

func (p *ProxyAuth) emailHeader() string {
	if p.EmailHeader != "" {
		return p.EmailHeader
	}
	return "X-Forwarded-Email"
}

type Connector struct {
	// URL is the connector's MCP endpoint on the internal network,
	// e.g. http://halopsa:7777/mcp
	URL string `json:"url"`
}

type Actor struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // human | automation

	// TokenSHA256 is the hex sha256 of the bearer token. The plaintext token
	// is never stored, so this file leaking does not hand over access.
	// Optional when Email is set (the actor authenticates via the SSO proxy).
	TokenSHA256 string `json:"token_sha256,omitempty"`

	// Email is the SSO identity (lowercased). When the trusted SSO proxy asserts
	// this email, the request resolves to this actor. Optional when a token is
	// set (a machine client). At least one of TokenSHA256 or Email is required.
	Email string `json:"email,omitempty"`

	// Admin marks an actor as allowed to reach the gateway's admin surface
	// (permissions editor, audit viewer). Off by default.
	Admin bool `json:"admin,omitempty"`

	// Grants is keyed by connector slug. An absent slug means no access.
	Grants map[string]Grant `json:"grants"`
}

type Grant struct {
	// AllowTools and DenyTools are glob patterns matched against tool names.
	// Deny wins. An empty AllowTools means "nothing", not "everything":
	// defaulting an unspecified permission to full access is how a config
	// typo becomes a breach.
	AllowTools []string `json:"allow_tools"`
	DenyTools  []string `json:"deny_tools"`

	// Write permits tools that are not annotated read-only. Absent means
	// read-only, which is the default posture for a shared always-on service.
	Write bool `json:"write"`
}

var hexSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// LoadConfig reads and validates the configuration. Every validation failure
// here is fatal at startup rather than surfacing as a confusing 403 later.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen is required, as host:port on a specific interface")
	}
	host, _, err := splitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen %q: %w", c.Listen, err)
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		// In a container a wildcard bind is correct: the network namespace is
		// the boundary and the compose `ports:` mapping restricts the host
		// side to one address. On bare metal it is how a gateway ends up
		// answering on an interface the operator believed was firewalled,
		// because Docker's published ports DNAT ahead of ufw and firewalld.
		//
		// So it is allowed, but only when something deliberately says so,
		// rather than by default.
		if os.Getenv("MSP_GATEWAY_ALLOW_WILDCARD_BIND") == "" {
			return fmt.Errorf(
				"listen %q binds every interface. Bind a specific LAN address, or set "+
					"MSP_GATEWAY_ALLOW_WILDCARD_BIND=1 if something else restricts the "+
					"host side (a container port mapping does; a host firewall may not, "+
					"because Docker DNATs ahead of ufw and firewalld)", c.Listen)
		}
	}
	if c.AuditLog == "" {
		return fmt.Errorf("audit_log is required; this deployment's whole claim is that actions are recorded")
	}
	switch c.ArgumentsMode {
	case "":
		c.ArgumentsMode = "hash"
	case "none", "hash", "full":
	default:
		return fmt.Errorf("arguments_mode %q: want none, hash or full", c.ArgumentsMode)
	}
	if len(c.Connectors) == 0 {
		return fmt.Errorf("no connectors configured")
	}
	for slug, conn := range c.Connectors {
		if !dnsSafe(slug) {
			return fmt.Errorf("connector %q is not a DNS-safe name", slug)
		}
		u, err := url.Parse(conn.URL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("connector %q: url %q is not absolute", slug, conn.URL)
		}
	}
	if len(c.Actors) == 0 {
		return fmt.Errorf("no actors configured; nobody could authenticate")
	}
	if c.ProxyAuth != nil && !hexSHA256.MatchString(c.ProxyAuth.SharedSecretSHA256) {
		return fmt.Errorf("proxy_auth.shared_secret_sha256 must be 64 lowercase hex characters")
	}
	seen := map[string]string{}      // token digest -> actor
	seenEmail := map[string]string{} // email -> actor
	for i, a := range c.Actors {
		if a.Name == "" {
			return fmt.Errorf("actor %d has no name", i)
		}
		// An actor authenticates by bearer token, by SSO email, or both. At
		// least one is required: an actor with neither can never be resolved.
		if a.TokenSHA256 == "" && a.Email == "" {
			return fmt.Errorf("actor %q: one of token_sha256 or email is required", a.Name)
		}
		if a.TokenSHA256 != "" {
			if !hexSHA256.MatchString(a.TokenSHA256) {
				return fmt.Errorf("actor %q: token_sha256 must be 64 lowercase hex characters", a.Name)
			}
			if prev, dup := seen[a.TokenSHA256]; dup {
				// Two actors sharing a token makes the audit log lie about who
				// acted, which defeats the point of having one.
				return fmt.Errorf("actors %q and %q share a token", prev, a.Name)
			}
			seen[a.TokenSHA256] = a.Name
		}
		if a.Email != "" {
			if a.Email != strings.ToLower(a.Email) {
				return fmt.Errorf("actor %q: email must be lowercase", a.Name)
			}
			if a.Email != "" && c.ProxyAuth == nil {
				return fmt.Errorf("actor %q has an email but proxy_auth is not configured", a.Name)
			}
			if prev, dup := seenEmail[a.Email]; dup {
				return fmt.Errorf("actors %q and %q share the email %q", prev, a.Name, a.Email)
			}
			seenEmail[a.Email] = a.Name
		}
		for slug := range a.Grants {
			if _, ok := c.Connectors[slug]; !ok {
				return fmt.Errorf("actor %q is granted unknown connector %q", a.Name, slug)
			}
		}
	}
	return nil
}

func dnsSafe(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i != 0 && i != len(s)-1:
		default:
			return false
		}
	}
	return true
}

func splitHostPort(hostport string) (string, string, error) {
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return "", "", fmt.Errorf("want host:port")
	}
	return strings.Trim(hostport[:i], "[]"), hostport[i+1:], nil
}
