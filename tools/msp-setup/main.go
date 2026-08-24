// msp-setup serves a LAN-only onboarding page for the connector fleet: pick a
// connector, fill in its credentials with real guidance, save.
//
// It deliberately holds nothing. Saves write straight through to the mounted
// secrets directory the connectors read from, the process keeps no copy, and
// the status endpoint reports variable NAMES only, never values. The
// connectors' entrypoints watch their secrets file and reload on change, so a
// save applies within seconds without this container having any Docker access.
// The Docker socket is root on the host; an onboarding web page must not hold
// it, and with the reload contract it does not need to.

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const secretsDir = "/secrets"

var (
	catalog   []byte
	authToken string
	varName   = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	slugName  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
)

func main() {
	raw, err := os.ReadFile("/opt/msp-setup/catalog.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "msp-setup: reading catalog: %v\n", err)
		os.Exit(1)
	}
	catalog = raw

	authToken = os.Getenv("MSP_SETUP_TOKEN")
	if authToken == "" {
		b := make([]byte, 18)
		if _, err := rand.Read(b); err != nil {
			fmt.Fprintf(os.Stderr, "msp-setup: entropy: %v\n", err)
			os.Exit(1)
		}
		authToken = hex.EncodeToString(b)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", pageHandler)
	mux.HandleFunc("/api/catalog", auth(catalogHandler))
	mux.HandleFunc("/api/status", auth(statusHandler))
	mux.HandleFunc("/api/save", auth(saveHandler))

	addr := os.Getenv("MSP_SETUP_ADDR")
	if addr == "" {
		addr = "0.0.0.0:8081"
	}
	fmt.Fprintf(os.Stderr, "msp-setup listening on %s\n", addr)
	fmt.Fprintf(os.Stderr, "open:  http://<host>:<port>/?token=%s\n", authToken)
	fmt.Fprintf(os.Stderr, "The token gates every API call. This page is for your LAN only.\n")
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "msp-setup: %v\n", err)
		os.Exit(1)
	}
}

// auth requires the startup token on every API call. The page itself is
// static and value-free, so it serves without auth; everything that reads
// state or writes credentials does not.
func auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := r.Header.Get("X-Setup-Token")
		if tok == "" {
			tok = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(authToken)) != 1 {
			http.Error(w, "missing or wrong setup token; it is printed in the container log at startup", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func catalogHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(catalog)
}

// statusHandler reports which connectors have a secrets file and which
// variable NAMES it holds. Values never leave the directory.
func statusHandler(w http.ResponseWriter, r *http.Request) {
	out := map[string]map[string]any{}
	entries, _ := os.ReadDir(secretsDir)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".env") || e.IsDir() {
			continue
		}
		slug := strings.TrimSuffix(name, ".env")
		raw, err := os.ReadFile(filepath.Join(secretsDir, name))
		if err != nil {
			out[slug] = map[string]any{"error": "unreadable"}
			continue
		}
		var vars []string
		for _, line := range strings.Split(string(raw), "\n") {
			if k, _, ok := strings.Cut(strings.TrimSpace(line), "="); ok && varName.MatchString(k) {
				vars = append(vars, k)
			}
		}
		sort.Strings(vars)
		out[slug] = map[string]any{"vars": vars}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

type saveRequest struct {
	Slug   string            `json:"slug"`
	Values map[string]string `json:"values"`
}

func saveHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req saveRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "bad JSON", http.StatusBadRequest)
		return
	}
	if !slugName.MatchString(req.Slug) {
		http.Error(w, "bad connector name", http.StatusBadRequest)
		return
	}
	var b strings.Builder
	names := make([]string, 0, len(req.Values))
	for k := range req.Values {
		names = append(names, k)
	}
	sort.Strings(names)
	kept := 0
	for _, k := range names {
		v := strings.TrimSpace(req.Values[k])
		if v == "" {
			continue
		}
		if !varName.MatchString(k) {
			http.Error(w, fmt.Sprintf("invalid variable name %q", k), http.StatusBadRequest)
			return
		}
		if strings.ContainsAny(v, "\n\r") {
			http.Error(w, fmt.Sprintf("%s contains a line break", k), http.StatusBadRequest)
			return
		}
		// The quotes trap, closed at the source: values arrive through JSON,
		// so shell-style quoting is never needed and never written.
		fmt.Fprintf(&b, "%s=%s\n", k, v)
		kept++
	}

	path := filepath.Join(secretsDir, req.Slug+".env")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o400); err != nil {
		http.Error(w, "writing secrets file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// uid 10001 is what the connectors run as; the container runs as root
	// exactly and only so this chown is possible.
	if err := os.Chown(tmp, 10001, 10001); err != nil {
		os.Remove(tmp)
		http.Error(w, "chown: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		http.Error(w, "rename: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"saved": true, "connector": req.Slug, "vars": kept,
		"note": "the connector reloads within a few seconds if it is running; a connector not yet enabled needs one compose command, shown on the page",
	})
}
