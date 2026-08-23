// Intuit token refresh. Hand-written; see skills/quickbooks/handfixes.json
// entry "oauth-env-and-auto-refresh".
//
// Lives here so both callers reach it: `auth refresh`, which persists
// deliberately, and the request path, which refreshes automatically when the
// cached access token is spent.

package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RefreshAccessToken exchanges a refresh token for a new access token (and
// possibly a rotated refresh token) against Intuit.
func RefreshAccessToken(ctx context.Context, tokenURL, clientID, clientSecret, refreshToken string) (string, string, int, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	// #nosec G704 -- tokenURL defaults to the hardcoded Intuit endpoint; the only override (QUICKBOOKS_TOKEN_URL) is a documented operator-set test hook, not attacker-controlled request input.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", 0, err
	}
	basic := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	req.Header.Set("Authorization", "Basic "+basic)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 30 * time.Second}
	// #nosec G704 -- see tokenURL note above; the request target is the trusted Intuit endpoint by default and only operator-overridable for tests.
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, fmt.Errorf("calling token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", "", 0, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", "", 0, fmt.Errorf("parsing token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", "", 0, fmt.Errorf("token endpoint returned no access_token")
	}
	if out.ExpiresIn == 0 {
		out.ExpiresIn = 3600
	}
	return out.AccessToken, out.RefreshToken, out.ExpiresIn, nil
}
