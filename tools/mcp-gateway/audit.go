package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one audited request. One line of JSON per event, appended, never
// rewritten, so the cost is O(1) per event no matter how large the log grows.
type Event struct {
	Seq        int64        `json:"seq"`
	PrevSHA256 string       `json:"prev_sha256"`
	TS         string       `json:"ts"`
	Actor      EventActor   `json:"actor"`
	Connector  string       `json:"connector"`
	MCP        EventMCP     `json:"mcp"`
	Policy     EventPolicy  `json:"policy"`
	Arguments  *EventArgs   `json:"arguments,omitempty"`
	Result     *EventResult `json:"result,omitempty"`
}

type EventActor struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	SourceIP string `json:"source_ip"`
}

type EventMCP struct {
	Method string `json:"method"`
	Tool   string `json:"tool,omitempty"`
}

type EventPolicy struct {
	Decision string `json:"decision"` // allow | deny
	Reason   string `json:"reason,omitempty"`
	Class    string `json:"class,omitempty"` // read | write | unclassified
}

type EventArgs struct {
	Mode   string          `json:"mode"` // none | hash | full
	SHA256 string          `json:"sha256,omitempty"`
	Value  json.RawMessage `json:"value,omitempty"`
}

type EventResult struct {
	Status     string `json:"status"`
	DurationMS int64  `json:"duration_ms"`
}

// Auditor appends hash-chained events. Each line carries the sha256 of the
// previous line, so removing or editing any line breaks the chain from that
// point on and `verify` reports exactly where.
type Auditor struct {
	mu   sync.Mutex
	f    *os.File
	prev string
	seq  int64
	now  func() time.Time
}

func NewAuditor(path string) (*Auditor, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating audit dir: %w", err)
	}
	prev, seq, err := tailChain(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	return &Auditor{f: f, prev: prev, seq: seq, now: time.Now}, nil
}

// Append writes one event, filling in seq, timestamp and chain link.
func (a *Auditor) Append(e *Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	e.Seq = a.seq
	e.PrevSHA256 = a.prev
	e.TS = a.now().UTC().Format(time.RFC3339Nano)

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshaling audit event: %w", err)
	}
	if _, err := a.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("writing audit event: %w", err)
	}
	sum := sha256.Sum256(line)
	a.prev = hex.EncodeToString(sum[:])
	return nil
}

func (a *Auditor) Close() error { return a.f.Close() }

// HashArguments renders tool arguments per the configured mode.
func HashArguments(mode string, raw json.RawMessage) *EventArgs {
	switch mode {
	case "none":
		return &EventArgs{Mode: "none"}
	case "full":
		return &EventArgs{Mode: "full", Value: raw}
	default:
		sum := sha256.Sum256(raw)
		return &EventArgs{Mode: "hash", SHA256: hex.EncodeToString(sum[:])}
	}
}
