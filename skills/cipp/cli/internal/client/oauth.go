// Azure AD client-credentials token minting. Hand-written; see
// skills/cipp/handfixes.json entry "cipp-oauth-env-and-refresh".
//
// Lives here rather than in internal/cli so both callers can reach it: `auth
// login`, which mints once and persists deliberately, and the request path,
// which re-mints in memory when the cached token has expired.

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientCredentialsToken exchanges a CIPP API client's credentials for a
// bearer token against Azure AD.
func ClientCredentialsToken(ctx context.Context, authority, tenantID, clientID, clientSecret, scope string) (string, time.Time, error) {
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", strings.TrimRight(authority, "/"), tenantID)
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("grant_type", "client_credentials")
	form.Set("scope", scope)

	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("requesting token from %s: %w", tokenURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		// Azure AD returns a JSON error body with error_description; surface it.
		var aadErr struct {
			Error     string `json:"error"`
			ErrorDesc string `json:"error_description"`
		}
		if json.Unmarshal(body, &aadErr) == nil && aadErr.Error != "" {
			desc := aadErr.ErrorDesc
			if i := strings.IndexByte(desc, '\n'); i > 0 {
				desc = desc[:i]
			}
			return "", time.Time{}, fmt.Errorf("token request failed (HTTP %d): %s: %s", resp.StatusCode, aadErr.Error, desc)
		}
		return "", time.Time{}, fmt.Errorf("token request failed (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", time.Time{}, fmt.Errorf("parsing token response: %w", err)
	}
	if tok.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("token response contained no access_token")
	}
	expiry := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second)
	if tok.ExpiresIn == 0 {
		expiry = time.Now().Add(time.Hour) // conservative default
	}
	return tok.AccessToken, expiry, nil
}
