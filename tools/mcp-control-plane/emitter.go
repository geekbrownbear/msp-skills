package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// The gateway's actor/grant shape (mirrors tools/mcp-gateway/config.go). The
// control plane writes an array of these to the file the gateway watches.
type gwGrant struct {
	AllowTools []string `json:"allow_tools,omitempty"`
	DenyTools  []string `json:"deny_tools,omitempty"`
	Write      bool     `json:"write,omitempty"`
}

type gwActor struct {
	Name        string             `json:"name"`
	Kind        string             `json:"kind"`
	Email       string             `json:"email,omitempty"`
	TokenSHA256 string             `json:"token_sha256,omitempty"`
	Admin       bool               `json:"admin,omitempty"`
	Grants      map[string]gwGrant `json:"grants,omitempty"`
}

// buildGatewayActors translates control-plane users into gateway actors. Each
// active user yields an email-authenticated actor plus one token-authenticated
// actor per personal access token, sharing the same grants.
func buildGatewayActors(users []*User) []gwActor {
	out := []gwActor{}
	for _, u := range users {
		if u.Disabled {
			continue
		}
		grants := map[string]gwGrant{}
		for slug, g := range u.Grants {
			switch g.Access {
			case "read":
				grants[slug] = gwGrant{AllowTools: []string{"*"}}
			case "write":
				grants[slug] = gwGrant{AllowTools: []string{"*"}, Write: true}
			}
		}
		base := gwActor{
			Name:   u.Name,
			Kind:   "human",
			Email:  u.Email,
			Admin:  u.Role.isAdmin(),
			Grants: grants,
		}
		out = append(out, base)
		for _, tk := range u.Tokens {
			a := base
			a.Name = fmt.Sprintf("%s [token: %s]", u.Name, tk.Label)
			a.TokenSHA256 = tk.Hash
			out = append(out, a)
		}
	}
	return out
}

// writeGatewayActors atomically writes the actors file the gateway hot-reloads.
// A no-op when path is empty (control plane running without a wired gateway).
func writeGatewayActors(path string, users []*User) error {
	if path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(buildGatewayActors(users), "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
