package main

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// oauthFlow is the pending state between /auth/<p>/start and the callback.
type oauthFlow struct {
	provider string
	nonce    string
	verifier string
	returnTo string // where to land after login (a pending delegated-SSO request)
	expires  time.Time
}

type flowStore struct {
	mu    sync.Mutex
	items map[string]oauthFlow
}

func newFlowStore() *flowStore { return &flowStore{items: map[string]oauthFlow{}} }

func (f *flowStore) put(state string, fl oauthFlow) {
	f.mu.Lock()
	f.items[state] = fl
	// opportunistic reap
	now := time.Now()
	for k, v := range f.items {
		if now.After(v.expires) {
			delete(f.items, k)
		}
	}
	f.mu.Unlock()
}

func (f *flowStore) take(state string) (oauthFlow, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fl, ok := f.items[state]
	if ok {
		delete(f.items, state)
	}
	if ok && time.Now().After(fl.expires) {
		return oauthFlow{}, false
	}
	return fl, ok
}

const oauthStateCookie = "cp_oauth_state"

// provider discovers (and caches) the OIDC provider for the issuer.
func (s *Server) oidcProvider(ctx context.Context, issuer string) (*oidc.Provider, error) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if p, ok := s.oidcCache[issuer]; ok {
		return p, nil
	}
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	if s.oidcCache == nil {
		s.oidcCache = map[string]*oidc.Provider{}
	}
	s.oidcCache[issuer] = p
	return p, nil
}

func (s *Server) oauthConfig(ctx context.Context, provider string) (*oidc.Provider, *oauth2.Config, ProviderConfig, error) {
	cfg := s.providers.Get().provider(provider)
	if !cfg.ready() {
		return nil, nil, cfg, errNotConfigured
	}
	p, err := s.oidcProvider(ctx, cfg.issuer(provider))
	if err != nil {
		return nil, nil, cfg, err
	}
	oc := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  s.externalURL + "/auth/" + provider + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	return p, oc, cfg, nil
}

var errNotConfigured = &ssoErr{"this sign-in method is not configured"}

type ssoErr struct{ msg string }

func (e *ssoErr) Error() string { return e.msg }

func (s *Server) handleSSOStart(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.providers == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		_, oc, _, err := s.oauthConfig(ctx, provider)
		if err != nil {
			s.render(w, "login", map[string]any{"CSRF": s.ensureCSRF(w, r), "SSO": s.ssoButtons(), "Error": "Sign-in with " + provider + " is unavailable."})
			return
		}
		state := randToken()
		nonce := randToken()
		verifier := oauth2.GenerateVerifier()
		s.flows.put(state, oauthFlow{provider: provider, nonce: nonce, verifier: verifier, returnTo: safeNext(r.URL.Query().Get("next")), expires: time.Now().Add(10 * time.Minute)})
		s.setCookie(w, r, oauthStateCookie, state, 10*time.Minute)
		url := oc.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
		http.Redirect(w, r, url, http.StatusSeeOther)
	}
}

func (s *Server) handleSSOCallback(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fail := func(msg string) {
			s.render(w, "login", map[string]any{"CSRF": s.ensureCSRF(w, r), "SSO": s.ssoButtons(), "Error": msg})
		}
		if s.providers == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if e := r.URL.Query().Get("error"); e != "" {
			fail("Sign-in was cancelled or failed.")
			return
		}
		state := r.URL.Query().Get("state")
		cookie, err := r.Cookie(oauthStateCookie)
		if err != nil || cookie.Value == "" || !subtleEqual(cookie.Value, state) {
			fail("Sign-in session expired. Try again.")
			return
		}
		s.clearCookie(w, r, oauthStateCookie)
		flow, ok := s.flows.take(state)
		if !ok || flow.provider != provider {
			fail("Sign-in session expired. Try again.")
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		p, oc, cfg, err := s.oauthConfig(ctx, provider)
		if err != nil {
			fail("Sign-in is unavailable.")
			return
		}
		tok, err := oc.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(flow.verifier))
		if err != nil {
			fail("Could not complete sign-in.")
			return
		}
		rawID, _ := tok.Extra("id_token").(string)
		if rawID == "" {
			fail("No identity token returned.")
			return
		}
		idToken, err := p.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(ctx, rawID)
		if err != nil {
			fail("Identity token could not be verified.")
			return
		}
		if idToken.Nonce != flow.nonce {
			fail("Sign-in could not be verified.")
			return
		}
		var claims struct {
			Email         string `json:"email"`
			EmailVerified bool   `json:"email_verified"`
			Name          string `json:"name"`
		}
		_ = idToken.Claims(&claims)
		email := normalizeEmail(claims.Email)
		if email == "" {
			fail("Your account did not return an email address.")
			return
		}
		s.ssoLogin(w, r, provider, email, claims.Name, flow.returnTo, fail)
	}
}

// ssoLogin resolves an SSO identity to a control-plane account: an existing
// account by email, or (if the email's domain is allowlisted for the provider)
// a newly auto-provisioned low-privilege user. Off-domain unknown emails are
// denied.
func (s *Server) ssoLogin(w http.ResponseWriter, r *http.Request, provider, email, name, returnTo string, fail func(string)) {
	if u := s.store.ByEmail(email); u != nil {
		if u.Disabled {
			fail("Your account is disabled.")
			return
		}
		s.startSession(w, r, u.Email)
		http.Redirect(w, r, s.loginDest(returnTo), http.StatusSeeOther)
		return
	}
	cfg := s.providers.Get().provider(provider)
	if domainAllowed(email, cfg.AllowedDomains) {
		if name == "" {
			name = email
		}
		if _, err := s.store.Create(&User{Email: email, Name: name, Role: RoleUser}); err != nil {
			fail("Could not create your account.")
			return
		}
		s.syncGateway()
		s.startSession(w, r, email)
		http.Redirect(w, r, s.loginDest(returnTo), http.StatusSeeOther)
		return
	}
	fail("No account exists for " + email + ". Ask an administrator to add you.")
}

// ssoButtons reports which providers are ready, for the login screen.
func (s *Server) ssoButtons() map[string]bool {
	if s.providers == nil {
		return nil
	}
	c := s.providers.Get()
	return map[string]bool{
		"microsoft": c.Microsoft.ready(),
		"google":    c.Google.ready(),
	}
}
