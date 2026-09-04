package main

import (
	"net/http"
	"strings"
)

func (s *Server) handleSSO(w http.ResponseWriter, r *http.Request) {
	csrf := s.ensureCSRF(w, r)
	cur := s.providers.Get()

	if r.Method == http.MethodGet {
		s.renderSSO(w, cur, csrf, "", "")
		return
	}
	if !s.checkCSRF(r) {
		s.renderSSO(w, cur, csrf, "Session expired, try again.", "")
		return
	}

	next := cur
	next.Microsoft.Enabled = r.FormValue("ms_enabled") == "on"
	next.Microsoft.TenantID = strings.TrimSpace(r.FormValue("ms_tenant"))
	next.Microsoft.ClientID = strings.TrimSpace(r.FormValue("ms_client_id"))
	if v := strings.TrimSpace(r.FormValue("ms_client_secret")); v != "" {
		next.Microsoft.ClientSecret = v // only overwrite when a new value is entered
	}
	next.Microsoft.AllowedDomains = parseDomains(r.FormValue("ms_domains"))

	next.Google.Enabled = r.FormValue("g_enabled") == "on"
	next.Google.ClientID = strings.TrimSpace(r.FormValue("g_client_id"))
	if v := strings.TrimSpace(r.FormValue("g_client_secret")); v != "" {
		next.Google.ClientSecret = v
	}
	next.Google.AllowedDomains = parseDomains(r.FormValue("g_domains"))

	if err := s.providers.Save(next); err != nil {
		s.renderSSO(w, cur, csrf, "Could not save configuration.", "")
		return
	}
	// The issuer may have changed (e.g. a new tenant); drop the discovery cache.
	s.oidcMu.Lock()
	s.oidcCache = nil
	s.oidcMu.Unlock()
	s.renderSSO(w, next, csrf, "", "Saved.")
}

// renderSSO renders the config screen. Client secrets are never written back
// into the page; only whether one is set.
func (s *Server) renderSSO(w http.ResponseWriter, cfg SSOConfig, csrf, errMsg, okMsg string) {
	s.render(w, "sso", map[string]any{
		"CSRF":  csrf,
		"Error": errMsg,
		"Saved": okMsg,

		"MSEnabled":   cfg.Microsoft.Enabled,
		"MSTenant":    cfg.Microsoft.TenantID,
		"MSClientID":  cfg.Microsoft.ClientID,
		"MSHasSecret": cfg.Microsoft.ClientSecret != "",
		"MSDomains":   strings.Join(cfg.Microsoft.AllowedDomains, ", "),

		"GEnabled":   cfg.Google.Enabled,
		"GClientID":  cfg.Google.ClientID,
		"GHasSecret": cfg.Google.ClientSecret != "",
		"GDomains":   strings.Join(cfg.Google.AllowedDomains, ", "),

		"External":   s.externalURL,
		"MSRedirect": s.externalURL + "/auth/microsoft/callback",
		"GRedirect":  s.externalURL + "/auth/google/callback",
	})
}
