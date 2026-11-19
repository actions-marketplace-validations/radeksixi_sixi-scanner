package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// JSONLLogger streams one JSON-encoded Attempt per line to a file with 0600
// permissions. Safe for concurrent use from engine worker goroutines.
type JSONLLogger struct {
	mu   sync.Mutex
	file *os.File
	enc  *json.Encoder
	err  error
}

// OpenJSONLLogger creates (or truncates) path with mode 0600 and returns a
// concurrent-safe line-delimited JSON attempt logger.
func OpenJSONLLogger(path string) (*JSONLLogger, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create log dir %s: %w", dir, err)
		}
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open --log-jsonl %s: %w", path, err)
	}
	enc := json.NewEncoder(f)
	enc.SetEscapeHTML(false)
	return &JSONLLogger{file: f, enc: enc}, nil
}

// Write appends one attempt as a single JSON line.
func (l *JSONLLogger) Write(a Attempt) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return
	}
	if err := l.enc.Encode(a); err != nil && l.err == nil {
		l.err = err
	}
}

// Close flushes and closes the underlying file, returning any write or close error.
func (l *JSONLLogger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return l.err
	}
	cerr := l.file.Close()
	l.file = nil
	if l.err != nil {
		return l.err
	}
	return cerr
}
