package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Delegated single sign-on: the control plane is the identity authority, and a
// trusted internal app (e.g. a console UI) sends users here to authenticate,
// then receives a short-lived signed ticket asserting who they are. The app
// establishes its own session from that ticket and, for gateway calls, forwards
// the user's email under the gateway's proxy_auth shared secret. No user
// credentials ever live in the app; the control plane remains the one place
// accounts, SSO and permissions are managed.
//
// The ticket is HMAC-signed with a secret shared only between the control plane
// and the app, is valid for 60 seconds, and is delivered only to an
// allowlisted redirect_uri. Wire format (compact, JWS-like):
//
//	base64url(json(ticketClaims)) "." base64url(hmac_sha256(key, part1))

type ticketClaims struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
	Exp   int64  `json:"exp"`
	Nonce string `json:"nonce"`
}

const ticketTTL = 60 * time.Second

func (s *Server) signTicket(c ticketClaims) string {
	payload, _ := json.Marshal(c)
	part1 := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, s.ssoTicketKey)
	mac.Write([]byte(part1))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return part1 + "." + sig
}

// handleSSOAuthorize is the delegated-login endpoint. The app sends the user
// here with an allowlisted redirect_uri and an opaque state. If the user has a
// control-plane session we mint a ticket and bounce back; otherwise we send them
// through login first and return here.
func (s *Server) handleSSOAuthorize(w http.ResponseWriter, r *http.Request) {
	if len(s.ssoTicketKey) == 0 || len(s.ssoAllowedRedirects) == 0 {
		http.Error(w, "delegated sign-on is not enabled", http.StatusNotFound)
		return
	}
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	if !s.redirectAllowed(redirectURI) {
		http.Error(w, "redirect_uri is not allowed", http.StatusBadRequest)
		return
	}
	u := s.currentUser(r)
	if u == nil {
		// Authenticate first, then return to this exact request.
		next := "/sso/authorize?" + r.URL.RawQuery
		http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}
	ticket := s.signTicket(ticketClaims{
		Email: u.Email,
		Name:  u.Name,
		Role:  string(u.Role),
		Exp:   time.Now().Add(ticketTTL).Unix(),
		Nonce: randToken(),
	})
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	dest := redirectURI + sep + "ticket=" + url.QueryEscape(ticket)
	if state != "" {
		dest += "&state=" + url.QueryEscape(state)
	}
	http.Redirect(w, r, dest, http.StatusSeeOther)
}

// redirectAllowed matches the requested redirect_uri against the operator's
// exact allowlist. Exact match only: a prefix check would let an open redirect
// on the app's origin leak tickets.
func (s *Server) redirectAllowed(uri string) bool {
	if uri == "" {
		return false
	}
	for _, allowed := range s.ssoAllowedRedirects {
		if uri == allowed {
			return true
		}
	}
	return false
}

// safeNext accepts only a same-origin relative path, never an absolute or
// scheme-relative URL, so ?next= can never be an open redirect off the box.
func safeNext(next string) string {
	if strings.HasPrefix(next, "/") && !strings.HasPrefix(next, "//") && !strings.HasPrefix(next, "/\\") {
		return next
	}
	return ""
}

// loginDest is where to send a user after a successful login: back to the
// pending delegated-SSO request if one is carried, otherwise the admin home.
func (s *Server) loginDest(next string) string {
	if n := safeNext(next); n != "" {
		return n
	}
	return "/admin"
}
