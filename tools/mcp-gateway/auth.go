package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"
)

// Authenticator resolves a bearer token to an actor.
//
// Tokens are compared by sha256 with crypto/subtle.ConstantTimeCompare. A
// naive == on the digests would still leak timing, and a token here is
// equivalent to a technician's access to every vendor they are granted.
type Authenticator struct {
	byDigest map[string]*Actor
}

func NewAuthenticator(actors []Actor) *Authenticator {
	a := &Authenticator{byDigest: make(map[string]*Actor, len(actors))}
	for i := range actors {
		a.byDigest[actors[i].TokenSHA256] = &actors[i]
	}
	return a
}

// Authenticate returns the actor for a request, or nil.
func (a *Authenticator) Authenticate(r *http.Request) *Actor {
	token := bearerToken(r)
	if token == "" {
		return nil
	}
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
