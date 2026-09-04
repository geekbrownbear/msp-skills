package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

// auditEvent mirrors the gateway's audit Event (the fields we display). The log
// is one JSON object per line, appended, hash-chained by prev_sha256.
type auditEvent struct {
	Seq        int64  `json:"seq"`
	PrevSHA256 string `json:"prev_sha256"`
	TS         string `json:"ts"`
	Actor      struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"actor"`
	Connector string `json:"connector"`
	MCP       struct {
		Method string `json:"method"`
		Tool   string `json:"tool"`
	} `json:"mcp"`
	Policy struct {
		Decision string `json:"decision"`
		Class    string `json:"class"`
		Reason   string `json:"reason"`
	} `json:"policy"`
	Result *struct {
		Status string `json:"status"`
	} `json:"result,omitempty"`
}

type auditReport struct {
	Configured bool
	Events     []auditEvent // newest first, capped
	Total      int
	ChainOK    bool
	ChainErr   string
}

// readAudit parses and verifies the hash-chained audit log, returning the most
// recent events (newest first). Verification recomputes each line's sha256 and
// checks the prev_sha256 linkage and sequence numbers, exactly as the gateway's
// verify-audit does; a broken chain means the log was edited or truncated.
func readAudit(path string, limit int) (auditReport, error) {
	rep := auditReport{ChainOK: true}
	if path == "" {
		return rep, nil
	}
	rep.Configured = true
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return rep, nil // no events yet
		}
		return rep, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var prev string
	var wantSeq int64
	var all []auditEvent
	line := 0
	for sc.Scan() {
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		line++
		wantSeq++
		var e auditEvent
		if err := json.Unmarshal(raw, &e); err != nil {
			rep.ChainOK, rep.ChainErr = false, fmt.Sprintf("line %d is not valid JSON", line)
			break
		}
		if rep.ChainOK {
			if e.PrevSHA256 != prev {
				rep.ChainOK, rep.ChainErr = false, fmt.Sprintf("chain broken at seq %d (line %d)", e.Seq, line)
			} else if e.Seq != wantSeq {
				rep.ChainOK, rep.ChainErr = false, fmt.Sprintf("sequence gap at line %d (expected %d, found %d)", line, wantSeq, e.Seq)
			}
		}
		sum := sha256.Sum256(raw)
		prev = hex.EncodeToString(sum[:])
		all = append(all, e)
	}
	if err := sc.Err(); err != nil {
		return rep, err
	}
	rep.Total = len(all)
	for i := len(all) - 1; i >= 0 && len(rep.Events) < limit; i-- {
		rep.Events = append(rep.Events, all[i])
	}
	return rep, nil
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	rep, err := readAudit(s.auditLogPath, 300)
	if err != nil {
		http.Error(w, "could not read audit log: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "audit", map[string]any{"Rep": rep})
}
