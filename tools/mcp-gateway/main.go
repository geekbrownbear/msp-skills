// msp-mcp-gateway authenticates technicians, authorizes them per connector and
// per tool, records every call in a hash-chained log, and proxies to the
// connector's MCP endpoint.
//
// Why this exists rather than a generic reverse proxy: a generic proxy sees
// "POST /mcp/halopsa" and a token. It cannot record which tool ran or refuse a
// write. Parsing one JSON-RPC envelope is the whole difference between
// "someone hit halopsa at 14:02" and "alice called tickets_delete at 14:02".
//
// Why not an off-the-shelf MCP gateway: the category exists (docker/mcp-gateway,
// IBM ContextForge, Obot) and every one of them assumes something upstream has
// already terminated identity. None authenticates the client connecting to it,
// which is the one thing an MSP cannot do without.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "msp-mcp-gateway: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/msp-mcp-gateway/gateway.json", "path to gateway.json")
	verify := flag.String("verify-audit", "", "verify the hash chain of an audit log and exit")
	flag.Parse()

	if *verify != "" {
		return VerifyChain(*verify, os.Stdout)
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	auditor, err := NewAuditor(cfg.AuditLog)
	if err != nil {
		return err
	}
	defer auditor.Close()

	gw, err := NewGateway(cfg, auditor)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: gw,
		// No WriteTimeout: MCP streams responses over SSE and a write deadline
		// would sever long-lived sessions mid-stream.
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		fmt.Fprintf(os.Stderr, "msp-mcp-gateway listening on %s for %d connector(s), %d actor(s)\n",
			cfg.Listen, len(cfg.Connectors), len(cfg.Actors))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return err
	case <-sig:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}
