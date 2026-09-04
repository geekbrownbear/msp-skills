package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

type Session struct {
	Token   string
	Email   string
	CSRF    string
	Expires time.Time
}

// Sessions is an in-memory session store. Sessions do not survive a restart,
// which simply means users log in again; nothing sensitive is persisted.
type Sessions struct {
	mu      sync.Mutex
	byToken map[string]*Session
	ttl     time.Duration
}

func NewSessions(ttl time.Duration) *Sessions {
	s := &Sessions{byToken: map[string]*Session{}, ttl: ttl}
	go s.reap()
	return s
}

func (s *Sessions) Create(email string) *Session {
	sess := &Session{
		Token:   randToken(),
		Email:   email,
		CSRF:    randToken(),
		Expires: time.Now().Add(s.ttl),
	}
	s.mu.Lock()
	s.byToken[sess.Token] = sess
	s.mu.Unlock()
	return sess
}

func (s *Sessions) Get(token string) *Session {
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.byToken[token]
	if sess == nil {
		return nil
	}
	if time.Now().After(sess.Expires) {
		delete(s.byToken, token)
		return nil
	}
	return sess
}

func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	delete(s.byToken, token)
	s.mu.Unlock()
}

func (s *Sessions) reap() {
	t := time.NewTicker(10 * time.Minute)
	for range t.C {
		now := time.Now()
		s.mu.Lock()
		for tok, sess := range s.byToken {
			if now.After(sess.Expires) {
				delete(s.byToken, tok)
			}
		}
		s.mu.Unlock()
	}
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
