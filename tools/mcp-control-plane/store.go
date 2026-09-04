package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Role string

const (
	RoleSuperAdmin Role = "superadmin"
	RoleAdmin      Role = "admin"
	RoleUser       Role = "user"
)

func (r Role) isAdmin() bool { return r == RoleSuperAdmin || r == RoleAdmin }

type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"` // lowercased, unique
	Name         string `json:"name"`
	PasswordHash string `json:"password_hash"`
	Role         Role   `json:"role"`
	Disabled     bool   `json:"disabled,omitempty"`
	CreatedAt    string `json:"created_at"`

	// Grants is per-connector access, keyed by connector slug.
	Grants map[string]CPGrant `json:"grants,omitempty"`
	// Tokens are personal access tokens (sha256 only), for non-Callisto clients.
	Tokens []TokenRef `json:"tokens,omitempty"`
}

// CPGrant is the control plane's per-connector access level. It is translated
// into the gateway's Grant (allow/deny globs + write) by the emitter.
type CPGrant struct {
	Access string `json:"access"` // none | read | write
}

type TokenRef struct {
	Hash      string `json:"hash"` // sha256 hex of the token; plaintext shown once
	Label     string `json:"label"`
	CreatedAt string `json:"created_at"`
}

var errEmailTaken = errors.New("a user with that email already exists")

// Store is a small JSON-backed user store. It is fine for the handful of staff
// accounts a control plane holds; writes are atomic (temp file + rename).
type Store struct {
	mu    sync.RWMutex
	path  string
	users map[string]*User // by lowercased email
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "users.json"), users: map[string]*User{}}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	var list []*User
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("users.json: %w", err)
	}
	for _, u := range list {
		s.users[u.Email] = u
	}
	return s, nil
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

func (s *Store) ByEmail(email string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u := s.users[normalizeEmail(email)]; u != nil {
		cp := *u
		return &cp
	}
	return nil
}

func (s *Store) List() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		cp := *u
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out
}

// Create adds a user. Email must be unique. ID and CreatedAt are set here.
func (s *Store) Create(u *User) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u.Email = normalizeEmail(u.Email)
	if u.Email == "" {
		return nil, errors.New("email is required")
	}
	if _, ok := s.users[u.Email]; ok {
		return nil, errEmailTaken
	}
	u.ID = newID()
	u.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	s.users[u.Email] = u
	if err := s.persistLocked(); err != nil {
		delete(s.users, u.Email)
		return nil, err
	}
	cp := *u
	return &cp, nil
}

// Update applies fn to a copy of the user and commits it atomically.
func (s *Store) Update(email string, fn func(*User) error) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[normalizeEmail(email)]
	if u == nil {
		return nil, errors.New("no such user")
	}
	cp := *u
	if err := fn(&cp); err != nil {
		return nil, err
	}
	s.users[cp.Email] = &cp
	if err := s.persistLocked(); err != nil {
		s.users[u.Email] = u
		return nil, err
	}
	r := cp
	return &r, nil
}

// Delete removes a user. The last remaining super admin cannot be deleted.
func (s *Store) Delete(email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	email = normalizeEmail(email)
	u := s.users[email]
	if u == nil {
		return errors.New("no such user")
	}
	if u.Role == RoleSuperAdmin && s.countSuperAdminsLocked() <= 1 {
		return errors.New("cannot delete the only super admin")
	}
	delete(s.users, email)
	if err := s.persistLocked(); err != nil {
		s.users[email] = u
		return err
	}
	return nil
}

func (s *Store) countSuperAdminsLocked() int {
	n := 0
	for _, u := range s.users {
		if u.Role == RoleSuperAdmin {
			n++
		}
	}
	return n
}

func (s *Store) persistLocked() error {
	list := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Email < list[j].Email })
	raw, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func normalizeEmail(e string) string {
	return strings.ToLower(strings.TrimSpace(e))
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
