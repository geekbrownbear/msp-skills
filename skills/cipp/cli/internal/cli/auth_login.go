// Copyright 2026 damienstevens and contributors. Licensed under Apache-2.0. See LICENSE.
// Hand-authored novel feature (preserved across regen). CIPP-specific OAuth2
// client-credentials login: CIPP is self-hosted and authenticates via an Azure
// AD app registration (the "API client" created in CIPP > Integrations >
// CIPP-API). This command performs the client-credentials token exchange
// against login.microsoftonline.com and caches the resulting bearer token.

package cli

import (
	"fmt"
	"strings"
	"time"

	"cipp-pp-cli/internal/client"
	"cipp-pp-cli/internal/cliutil"
	"cipp-pp-cli/internal/config"

	"github.com/spf13/cobra"
)

func newAuthLoginCmd(flags *rootFlags) *cobra.Command {
	var clientID, clientSecret, tenantID, baseURL, scope, authority string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate to a self-hosted CIPP instance via OAuth2 client credentials",
		Long: strings.Trim(`
Exchange a CIPP API client's credentials for a bearer token and cache it.

CIPP is self-hosted, so each MSP runs its own instance. Create an API client in
CIPP > Integrations > CIPP-API (use a read-only Custom Role for safe testing),
then run this command with the Client ID, Client Secret, Tenant ID, and the API
base URL it shows you. The base URL must include /api
(e.g. https://cipp.yourmsp.com/api).

This performs the Azure AD client-credentials flow against
https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token with
scope api://{client-id}/.default and caches the access token to expiry. To use a
static bearer token instead, set CIPP_API_KEY or run 'auth set-token'.`, "\n"),
		Example: strings.Trim(`
  cipp-cli auth login \
    --client-id 00000000-0000-0000-0000-000000000000 \
    --client-secret 'your-secret' \
    --tenant-id 11111111-1111-1111-1111-111111111111 \
    --base-url https://cipp.yourmsp.com/api`, "\n"),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Bare invocation prints help rather than a terse flag error.
			if clientID == "" && clientSecret == "" && tenantID == "" && baseURL == "" {
				return cmd.Help()
			}
			if dryRunOK(flags) {
				return nil
			}

			missing := []string{}
			if clientID == "" {
				missing = append(missing, "--client-id")
			}
			if clientSecret == "" {
				missing = append(missing, "--client-secret")
			}
			if tenantID == "" {
				missing = append(missing, "--tenant-id")
			}
			if baseURL == "" {
				missing = append(missing, "--base-url")
			}
			if len(missing) > 0 {
				return fmt.Errorf("missing required flag(s): %s", strings.Join(missing, ", "))
			}

			if scope == "" {
				scope = "api://" + clientID + "/.default"
			}
			if authority == "" {
				authority = "https://login.microsoftonline.com"
			}
			baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
			if !strings.HasSuffix(strings.ToLower(baseURL), "/api") {
				fmt.Fprintf(cmd.ErrOrStderr(),
					"warning: --base-url does not end in /api; CIPP requests will hit the static web UI, not the Functions backend. Got: %s\n", baseURL)
			}

			w := cmd.OutOrStdout()

			// Verify-mode: never dial out. Report what would happen and succeed.
			if cliutil.IsVerifyEnv() {
				fmt.Fprintf(w, "would authenticate client %s against %s/%s/oauth2/v2.0/token (verify mode)\n", clientID, authority, tenantID)
				return nil
			}

			token, expiry, err := client.ClientCredentialsToken(cmd.Context(), authority, tenantID, clientID, clientSecret, scope)
			if err != nil {
				return err
			}

			cfg, err := config.Load(flags.configPath)
			if err != nil {
				return configErr(err)
			}
			cfg.BaseURL = baseURL
			if err := cfg.SaveTokens(clientID, clientSecret, token, "", expiry); err != nil {
				return fmt.Errorf("caching token: %w", err)
			}

			fmt.Fprintf(w, "Authenticated. Token cached to %s, expires %s.\n", cfg.Path, expiry.Format(time.RFC3339))
			fmt.Fprintf(w, "Base URL set to %s. Run 'cipp-cli doctor' to verify connectivity.\n", baseURL)
			return nil
		},
	}

	cmd.Flags().StringVar(&clientID, "client-id", "", "Azure AD application (client) ID of the CIPP API client")
	cmd.Flags().StringVar(&clientSecret, "client-secret", "", "Client secret for the CIPP API client")
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "Azure AD tenant (directory) ID that hosts the CIPP API app registration")
	cmd.Flags().StringVar(&baseURL, "base-url", "", "CIPP API base URL, must include /api (e.g. https://cipp.yourmsp.com/api)")
	cmd.Flags().StringVar(&scope, "scope", "", "OAuth2 scope (default: api://<client-id>/.default)")
	cmd.Flags().StringVar(&authority, "authority", "", "Token authority host (default: https://login.microsoftonline.com)")
	return cmd
}

// cippClientCredentialsToken performs the Azure AD client-credentials grant and
// returns the access token plus its computed expiry time.
