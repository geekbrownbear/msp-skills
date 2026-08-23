// Copyright 2026 Damien Stevens and contributors. Licensed under Apache-2.0. See LICENSE.

package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"quickbooks-pp-cli/internal/client"
	"quickbooks-pp-cli/internal/cliutil"
	"quickbooks-pp-cli/internal/config"
)

// intuitTokenURL is the QuickBooks OAuth 2.0 token endpoint. Override with
// QUICKBOOKS_TOKEN_URL for testing.
// #nosec G101 -- public Intuit OAuth endpoint URL, not a credential; the "bearer" path segment trips the heuristic. Real secrets come from env/config.
const intuitTokenURL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"

func newAuthRefreshCmd(flags *rootFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "refresh",
		Short: "Mint a fresh access token from your OAuth2 refresh token",
		Long: "Exchange a QuickBooks OAuth 2.0 refresh token for a new access token and persist\n" +
			"it to the config. Access tokens expire after about an hour; refresh tokens last\n" +
			"~100 days and rotate on each refresh. Reads QUICKBOOKS_CLIENT_ID,\n" +
			"QUICKBOOKS_CLIENT_SECRET, and QUICKBOOKS_REFRESH_TOKEN from the environment or\n" +
			"the stored config.",
		Example:     "  quickbooks-cli auth refresh\n  quickbooks-cli auth refresh --json",
		Annotations: map[string]string{"mcp:hidden": "true"},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(flags.configPath)
			if err != nil {
				return configErr(err)
			}
			clientID := firstNonEmpty(os.Getenv("QUICKBOOKS_CLIENT_ID"), cfg.ClientID)
			clientSecret := firstNonEmpty(os.Getenv("QUICKBOOKS_CLIENT_SECRET"), cfg.ClientSecret)
			refreshToken := firstNonEmpty(os.Getenv("QUICKBOOKS_REFRESH_TOKEN"), cfg.RefreshToken)
			if clientID == "" || clientSecret == "" || refreshToken == "" {
				return authErr(fmt.Errorf("auth refresh needs QUICKBOOKS_CLIENT_ID, QUICKBOOKS_CLIENT_SECRET, and QUICKBOOKS_REFRESH_TOKEN (set in env or saved via `auth set-token`)"))
			}

			tokenURL := firstNonEmpty(os.Getenv("QUICKBOOKS_TOKEN_URL"), intuitTokenURL)

			// Verify/dry-run short-circuit: never make the network call during a
			// printing-press verify pass or a --dry-run, so the credential
			// requirement and the token endpoint stay untouched.
			if dryRunOK(flags) || cliutil.IsVerifyEnv() {
				if flags.asJSON {
					return printJSONFiltered(cmd.OutOrStdout(), map[string]any{
						"would_refresh": true,
						"token_url":     tokenURL,
						"config_path":   cfg.Path,
					}, flags)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "would refresh access token via %s\n", tokenURL)
				return nil
			}

			access, newRefresh, expiresIn, err := client.RefreshAccessToken(cmd.Context(), tokenURL, clientID, clientSecret, refreshToken)
			if err != nil {
				return authErr(err)
			}
			if newRefresh == "" {
				newRefresh = refreshToken // not all responses rotate
			}
			expiry := time.Now().Add(time.Duration(expiresIn) * time.Second)
			cfg.AuthHeaderVal = ""
			if err := cfg.SaveTokens(clientID, clientSecret, access, newRefresh, expiry); err != nil {
				return configErr(fmt.Errorf("saving refreshed token: %w", err))
			}

			if flags.asJSON {
				return printJSONFiltered(cmd.OutOrStdout(), map[string]any{
					"refreshed":   true,
					"expires_in":  expiresIn,
					"expires_at":  expiry.UTC().Format(time.RFC3339),
					"config_path": cfg.Path,
				}, flags)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Access token refreshed (expires in %ds); saved to %s\n", expiresIn, cfg.Path)
			return nil
		},
	}
	return cmd
}

// refreshAccessToken performs the OAuth2 refresh_token grant against the Intuit
// token endpoint and returns the new access token, rotated refresh token, and
// access-token lifetime in seconds.

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
