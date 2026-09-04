package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"
)

func (s *Server) renderAdmin(w http.ResponseWriter, r *http.Request, extra map[string]any) {
	u := r.Context().Value(userKey).(*User)
	fresh := s.store.ByEmail(u.Email)
	if fresh == nil {
		fresh = u
	}
	data := map[string]any{
		"User":    fresh,
		"Users":   s.store.List(),
		"IsAdmin": u.Role.isAdmin(),
		"CSRF":    s.ensureCSRF(w, r),
	}
	for k, v := range extra {
		data[k] = v
	}
	s.render(w, "admin", data)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	s.renderAdmin(w, r, nil)
}

var roleOptions = []Role{RoleUser, RoleAdmin, RoleSuperAdmin}

func (s *Server) handleUserNew(w http.ResponseWriter, r *http.Request) {
	csrf := s.ensureCSRF(w, r)
	if r.Method == http.MethodGet {
		s.render(w, "newuser", map[string]any{"CSRF": csrf, "Roles": roleOptions})
		return
	}
	if !s.checkCSRF(r) {
		s.render(w, "newuser", map[string]any{"CSRF": csrf, "Roles": roleOptions, "Error": "Session expired."})
		return
	}
	email := normalizeEmail(r.FormValue("email"))
	name := strings.TrimSpace(r.FormValue("name"))
	role := Role(r.FormValue("role"))
	pw := r.FormValue("password")
	if !validRole(role) {
		role = RoleUser
	}
	if msg := validateNewAccount(email, name, pw, pw); msg != "" {
		s.render(w, "newuser", map[string]any{"CSRF": csrf, "Roles": roleOptions, "Error": msg})
		return
	}
	hash, err := HashPassword(pw)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := s.store.Create(&User{Email: email, Name: name, PasswordHash: hash, Role: role}); err != nil {
		s.render(w, "newuser", map[string]any{"CSRF": csrf, "Roles": roleOptions, "Error": err.Error()})
		return
	}
	s.syncGateway()
	http.Redirect(w, r, "/admin/user?email="+email, http.StatusSeeOther)
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	csrf := s.ensureCSRF(w, r)
	email := normalizeEmail(r.FormValue("email"))
	target := s.store.ByEmail(email)
	if target == nil {
		http.Error(w, "no such user", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodGet {
		s.renderManage(w, target, csrf, "")
		return
	}
	if !s.checkCSRF(r) {
		s.renderManage(w, target, csrf, "Session expired.")
		return
	}

	switch r.FormValue("action") {
	case "permissions":
		grants := map[string]CPGrant{}
		for _, c := range connectors() {
			switch r.FormValue("grant_" + c.Slug) {
			case "read":
				grants[c.Slug] = CPGrant{Access: "read"}
			case "write":
				grants[c.Slug] = CPGrant{Access: "write"}
			}
		}
		s.store.Update(email, func(u *User) error { u.Grants = grants; return nil })
	case "role":
		role := Role(r.FormValue("role"))
		if !validRole(role) {
			s.renderManage(w, target, csrf, "Invalid role.")
			return
		}
		if target.Role == RoleSuperAdmin && role != RoleSuperAdmin && s.superAdminCount() <= 1 {
			s.renderManage(w, target, csrf, "Cannot demote the only super admin.")
			return
		}
		s.store.Update(email, func(u *User) error { u.Role = role; return nil })
	case "disable":
		if target.Role == RoleSuperAdmin && s.superAdminCount() <= 1 {
			s.renderManage(w, target, csrf, "Cannot disable the only super admin.")
			return
		}
		s.store.Update(email, func(u *User) error { u.Disabled = true; return nil })
	case "enable":
		s.store.Update(email, func(u *User) error { u.Disabled = false; return nil })
	case "reset":
		pw := r.FormValue("password")
		if len(pw) < minPassword {
			s.renderManage(w, target, csrf, "Password must be at least 12 characters.")
			return
		}
		hash, err := HashPassword(pw)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		s.store.Update(email, func(u *User) error { u.PasswordHash = hash; return nil })
	case "delete":
		if err := s.store.Delete(email); err != nil {
			s.renderManage(w, target, csrf, err.Error())
			return
		}
		s.syncGateway()
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	s.syncGateway()
	http.Redirect(w, r, "/admin/user?email="+email, http.StatusSeeOther)
}

func (s *Server) renderManage(w http.ResponseWriter, target *User, csrf, errMsg string) {
	type row struct {
		Slug, Name, Access string
	}
	rows := make([]row, 0, len(connectors()))
	for _, c := range connectors() {
		access := "none"
		if g, ok := target.Grants[c.Slug]; ok && g.Access != "" {
			access = g.Access
		}
		rows = append(rows, row{c.Slug, c.Name, access})
	}
	s.render(w, "manageuser", map[string]any{
		"CSRF": csrf, "T": target, "Rows": rows, "Roles": roleOptions, "Error": errMsg,
	})
}

// handleToken manages the current user's personal access tokens (self-service).
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !s.checkCSRF(r) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	u := r.Context().Value(userKey).(*User)
	switch r.FormValue("action") {
	case "mint":
		label := strings.TrimSpace(r.FormValue("label"))
		if label == "" {
			label = "token"
		}
		plain := randToken()
		ref := TokenRef{Hash: hashToken(plain), Label: label, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
		s.store.Update(u.Email, func(x *User) error {
			x.Tokens = append(x.Tokens, ref)
			return nil
		})
		s.syncGateway()
		// Show the plaintext once; it is never stored or shown again.
		s.renderAdmin(w, r, map[string]any{"NewToken": plain, "NewTokenLabel": label})
		return
	case "revoke":
		hash := r.FormValue("hash")
		s.store.Update(u.Email, func(x *User) error {
			out := x.Tokens[:0]
			for _, t := range x.Tokens {
				if t.Hash != hash {
					out = append(out, t)
				}
			}
			x.Tokens = out
			return nil
		})
		s.syncGateway()
	}
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) superAdminCount() int {
	n := 0
	for _, u := range s.store.List() {
		if u.Role == RoleSuperAdmin {
			n++
		}
	}
	return n
}

func validRole(r Role) bool {
	return r == RoleUser || r == RoleAdmin || r == RoleSuperAdmin
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}
