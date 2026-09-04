package main

import (
	"log"
	"net/http"
	"os"
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
