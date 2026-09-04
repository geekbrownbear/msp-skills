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
