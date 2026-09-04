package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
)

// Authenticator resolves a request to an actor by one of two paths:
//
//   - Bearer token (machine clients, and humans without SSO): the token is
//     compared by sha256 with crypto/subtle.ConstantTimeCompare. A naive == on
//     the digests would still leak timing, and a token here is equivalent to a
//     technician's access to every vendor they are granted.
//   - SSO proxy header: when a trusted proxy (oauth2-proxy/Authentik) sits in
//     front and asserts the user's email, the request resolves to the matching
//     actor. The identity header is only honored when the request also carries
//     the shared secret, so an internal peer cannot forge an identity.
type Authenticator struct {
	byDigest map[string]*Actor
	byEmail  map[string]*Actor
	proxy    *proxyTrust
}

type proxyTrust struct {
	secretDigest string // sha256 hex of the shared secret
	trustHeader  string
	emailHeader  string
}

func NewAuthenticator(actors []Actor, proxyAuth *ProxyAuth) *Authenticator {
	a := &Authenticator{
		byDigest: make(map[string]*Actor, len(actors)),
		byEmail:  make(map[string]*Actor, len(actors)),
	}
	for i := range actors {
		if actors[i].TokenSHA256 != "" {
			a.byDigest[actors[i].TokenSHA256] = &actors[i]
		}
		if actors[i].Email != "" {
			a.byEmail[strings.ToLower(actors[i].Email)] = &actors[i]
		}
	}
	if proxyAuth != nil {
		a.proxy = &proxyTrust{
			secretDigest: proxyAuth.SharedSecretSHA256,
			trustHeader:  proxyAuth.trustHeader(),
			emailHeader:  proxyAuth.emailHeader(),
		}
	}
	return a
}

// Authenticate returns the actor for a request, or nil.
func (a *Authenticator) Authenticate(r *http.Request) *Actor {
	if token := bearerToken(r); token != "" {
		return a.byToken(token)
	}
	return a.byProxyHeader(r)
}

func (a *Authenticator) byToken(token string) *Actor {
	sum := sha256.Sum256([]byte(token))
	digest := hex.EncodeToString(sum[:])
	// Walk every actor rather than indexing the map directly, so the work done
	// does not depend on whether the digest exists. The map lookup alone would
	// be a plausible timing oracle for "is this a known token".
	var found *Actor
	for known, actor := range a.byDigest {
		if subtle.ConstantTimeCompare([]byte(known), []byte(digest)) == 1 {
			found = actor
		}
	}
	return found
}

func (a *Authenticator) byProxyHeader(r *http.Request) *Actor {
	if a.proxy == nil {
		return nil
	}
	// The identity header is only trustworthy when the request also carries the
	// shared secret that only the front proxy knows. Compare in constant time.
	presented := r.Header.Get(a.proxy.trustHeader)
	if presented == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(presented))
	presentedDigest := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(a.proxy.secretDigest), []byte(presentedDigest)) != 1 {
		return nil
	}
	email := strings.ToLower(strings.TrimSpace(r.Header.Get(a.proxy.emailHeader)))
	if email == "" {
		return nil
	}
	return a.byEmail[email]
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(rest)
}
