package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// AuditLogger manages persistent audit logging to a JSONL file alongside
// the in-memory ring buffer.
type AuditLogger struct {
	mu       sync.Mutex
	file     *os.File
	filePath string
	entries  int64
}

// NewAuditLogger creates a new audit logger writing to the given file path.
// If path is empty, audit logging is in-memory only (no persistence).
func NewAuditLogger(path string) (*AuditLogger, error) {
	if path == "" {
		return &AuditLogger{}, nil
	}

	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create audit log directory: %w", err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open audit log file: %w", err)
	}

	return &AuditLogger{
		file:     f,
		filePath: path,
	}, nil
}

// Write persists an audit entry to disk as a JSON line.
func (al *AuditLogger) Write(entry AuditEntry) {
	if al.file == nil {
		return
	}

	al.mu.Lock()
	defer al.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		logrus.WithError(err).Error("failed to marshal audit entry")
		return
	}

	if _, err := al.file.Write(append(data, '\n')); err != nil {
		logrus.WithError(err).Error("failed to write audit log entry")
	}
	al.entries++
}

// Rotate closes the current log file and starts a new one with a timestamp suffix.
// The old file is renamed to path.YYYYMMDD-HHMMSS.
func (al *AuditLogger) Rotate() error {
	if al.file == nil {
		return nil
	}

	al.mu.Lock()
	defer al.mu.Unlock()

	// Close current file
	if err := al.file.Close(); err != nil {
		return fmt.Errorf("close current audit log: %w", err)
	}

	// Rename with timestamp
	ts := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", al.filePath, ts)
	if err := os.Rename(al.filePath, rotatedPath); err != nil {
		return fmt.Errorf("rotate audit log: %w", err)
	}

	// Open new file
	f, err := os.OpenFile(al.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("open new audit log: %w", err)
	}
	al.file = f
	al.entries = 0

	logrus.WithField("rotated_to", rotatedPath).Info("audit log rotated")
	return nil
}

// Close flushes and closes the audit log file.
func (al *AuditLogger) Close() error {
	if al.file == nil {
		return nil
	}
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.file.Close()
}

// Entries returns the count of entries written since last rotation.
func (al *AuditLogger) Entries() int64 {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.entries
}
