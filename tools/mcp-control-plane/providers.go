package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ProviderConfig is one SSO provider's settings, entered by the super admin in
// the admin UI. Secrets are stored on the data volume (0600); the control plane
// is the only thing that reads them.
type ProviderConfig struct {
	Enabled        bool     `json:"enabled"`
	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret"`
	TenantID       string   `json:"tenant_id,omitempty"` // Microsoft (Entra) only
	AllowedDomains []string `json:"allowed_domains,omitempty"`
}

func (p ProviderConfig) ready() bool {
	return p.Enabled && p.ClientID != "" && p.ClientSecret != ""
}

// issuer is the OIDC issuer URL for discovery.
func (p ProviderConfig) issuer(provider string) string {
	switch provider {
	case "microsoft":
		tenant := p.TenantID
		if tenant == "" {
			tenant = "common"
		}
		return "https://login.microsoftonline.com/" + tenant + "/v2.0"
	case "google":
		return "https://accounts.google.com"
	}
	return ""
}

type SSOConfig struct {
	Microsoft ProviderConfig `json:"microsoft"`
	Google    ProviderConfig `json:"google"`
}

func (c SSOConfig) provider(name string) ProviderConfig {
	if name == "microsoft" {
		return c.Microsoft
	}
	return c.Google
}

// ProviderStore persists the SSO configuration as sso.json.
type ProviderStore struct {
	mu   sync.RWMutex
	path string
	cfg  SSOConfig
}

func NewProviderStore(dir string) (*ProviderStore, error) {
	s := &ProviderStore{path: filepath.Join(dir, "sso.json")}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(raw, &s.cfg); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ProviderStore) Get() SSOConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *ProviderStore) Save(cfg SSOConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.cfg = cfg
	return nil
}

// domainAllowed reports whether an email's domain is on the allowlist. An empty
// allowlist means no auto-provisioning (deny unknown emails).
func domainAllowed(email string, allowed []string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	for _, d := range allowed {
		if strings.EqualFold(strings.TrimSpace(d), domain) {
			return true
		}
	}
	return false
}

func parseDomains(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if f = strings.TrimSpace(strings.ToLower(f)); f != "" {
			out = append(out, f)
		}
	}
	return out
}
