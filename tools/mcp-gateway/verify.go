package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// tailChain reads an existing audit log and returns the hash of its last line
// and the highest sequence number, so a restart continues the same chain
// rather than starting a new one that verify would read as a break.
func tailChain(path string) (prev string, seq int64, err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return "", 0, fmt.Errorf("audit log line %d is not valid JSON: %w", seq+1, err)
		}
		seq = e.Seq
		sum := sha256.Sum256(line)
		prev = hex.EncodeToString(sum[:])
	}
	if err := sc.Err(); err != nil {
		return "", 0, fmt.Errorf("reading audit log: %w", err)
	}
	return prev, seq, nil
}

// VerifyChain walks the log and reports the first break.
//
// The point is not to make tampering impossible, which nothing running on the
// same host can promise. It is to make tampering detectable: an edited or
// deleted line breaks every hash after it, and this names the sequence number
// where that starts.
func VerifyChain(path string, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening audit log: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	var (
		prev    string
		count   int64
		wantSeq int64
	)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		count++
		wantSeq++
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("line %d: invalid JSON: %w", count, err)
		}
		if e.PrevSHA256 != prev {
			return fmt.Errorf(
				"chain broken at seq %d (line %d): recorded prev_sha256 %q, computed %q. "+
					"A line at or before this point was edited or removed",
				e.Seq, count, e.PrevSHA256, prev)
		}
		if e.Seq != wantSeq {
			return fmt.Errorf("sequence gap at line %d: expected seq %d, found %d", count, wantSeq, e.Seq)
		}
		sum := sha256.Sum256(line)
		prev = hex.EncodeToString(sum[:])
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("reading audit log: %w", err)
	}
	fmt.Fprintf(out, "audit chain intact: %d event(s)\n", count)
	return nil
}
