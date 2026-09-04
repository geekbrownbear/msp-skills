package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	dir := envOr("CONTROL_PLANE_DATA_DIR", "/data")
	addr := envOr("CONTROL_PLANE_ADDR", ":8090")

	store, err := NewStore(dir)
	if err != nil {
		log.Fatalf("control plane: %v", err)
	}
	sessions := NewSessions(12 * time.Hour)
	srv := NewServer(store, sessions, os.Getenv("CONTROL_PLANE_GATEWAY_ACTORS_FILE"))
	srv.auditLogPath = os.Getenv("CONTROL_PLANE_AUDIT_LOG")
	srv.externalURL = strings.TrimRight(os.Getenv("CONTROL_PLANE_EXTERNAL_URL"), "/")
	if key := os.Getenv("CONTROL_PLANE_SSO_TICKET_KEY"); key != "" {
		srv.ssoTicketKey = []byte(key)
	}
	srv.ssoAllowedRedirects = splitList(os.Getenv("CONTROL_PLANE_SSO_ALLOWED_REDIRECTS"))
	providers, err := NewProviderStore(dir)
	if err != nil {
		log.Fatalf("control plane: %v", err)
	}
	srv.providers = providers
	srv.syncGateway() // emit current state on boot

	s := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("control plane listening on %s (%d account(s))", addr, store.Count())
	log.Fatal(s.ListenAndServe())
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// splitList parses a comma-separated env value into trimmed, non-empty entries.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
