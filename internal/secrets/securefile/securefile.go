// Package securefile creates memory-backed files readable by path.
// On Linux, files are backed by memfd (never touch disk). On macOS,
// files are unlinked temp files (page cache only, may touch swap).
//
// Two creation modes control fd inheritance by child processes:
//   - Create: inheritable fd (for shadow directory securefiles
//     that plugin subprocesses need to read)
//   - CreateCloexec: non-inheritable fd (for core-only consumers
//     like TLS cert/key and OAuth2 credentials)
package securefile

import (
	"fmt"
	"os"
	"sync"
)

// SecureFile is a memory-backed file accessible via a path. The
// file exists only in memory (Linux) or is unlinked from the
// filesystem immediately after creation (macOS). Close releases
// the memory.
type SecureFile struct {
	fd        *os.File
	path      string
	closeOnce sync.Once
	closeErr  error
}

// Path returns the path that other code can use to read this file.
// On Linux: "/proc/self/fd/<N>". On macOS: "/dev/fd/<N>".
func (f *SecureFile) Path() string {
	return f.path
}

// Write writes data into the secure file and seeks back to the
// start so readers see the full content.
func (f *SecureFile) Write(data []byte) error {
	if err := f.fd.Truncate(0); err != nil {
		return fmt.Errorf("truncate securefile: %w", err)
	}
	if _, err := f.fd.Seek(0, 0); err != nil {
		return fmt.Errorf("seek securefile: %w", err)
	}
	if _, err := f.fd.Write(data); err != nil {
		return fmt.Errorf("write securefile: %w", err)
	}
	if _, err := f.fd.Seek(0, 0); err != nil {
		return fmt.Errorf("seek securefile: %w", err)
	}
	return nil
}

// Close closes the file descriptor. On Linux, this releases the
// memory (memfd has no other references). On macOS, the unlinked
// file's disk blocks are freed. Safe to call multiple times.
func (f *SecureFile) Close() error {
	f.closeOnce.Do(func() {
		_ = f.fd.Truncate(0)
		f.closeErr = f.fd.Close()
	})
	return f.closeErr
}

// Tracker manages a collection of SecureFiles with per-plugin
// tracking. Thread-safe.
type Tracker struct {
	mu    sync.Mutex
	files map[string][]*SecureFile // plugin name → files
	dirs  map[string]string        // plugin name → shadow dir
}

// NewTracker creates a new securefile Tracker.
func NewTracker() *Tracker {
	return &Tracker{
		files: make(map[string][]*SecureFile),
		dirs:  make(map[string]string),
	}
}

// TrackForPlugin adds a SecureFile to the tracker under the given
// plugin name.
func (t *Tracker) TrackForPlugin(name string, f *SecureFile) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.files[name] = append(t.files[name], f)
}

// TrackDirForPlugin records a shadow directory path for cleanup.
func (t *Tracker) TrackDirForPlugin(name, dir string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dirs[name] = dir
}

// ClosePlugin closes all SecureFiles for the named plugin and
// removes its shadow directory if any.
func (t *Tracker) ClosePlugin(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, f := range t.files[name] {
		_ = f.Close()
	}
	delete(t.files, name)

	if dir, ok := t.dirs[name]; ok {
		_ = os.RemoveAll(dir)
		delete(t.dirs, name)
	}
	if dir, ok := t.dirs[name+"-base"]; ok {
		_ = os.RemoveAll(dir)
		delete(t.dirs, name+"-base")
	}
}

// CloseAll closes all tracked SecureFiles and removes all shadow
// directories.
func (t *Tracker) CloseAll() {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, files := range t.files {
		for _, f := range files {
			_ = f.Close()
		}
	}
	t.files = make(map[string][]*SecureFile)

	for _, dir := range t.dirs {
		_ = os.RemoveAll(dir)
	}
	t.dirs = make(map[string]string)
}
