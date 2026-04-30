//go:build linux

package securefile

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Create returns a new SecureFile backed by memfd. The fd is
// inheritable by child processes (no MFD_CLOEXEC). Use for shadow
// directory securefiles where plugin subprocesses need to read
// via /proc/self/fd/N.
func Create(name string) (*SecureFile, error) {
	fd, err := unix.MemfdCreate(name, 0)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	return &SecureFile{
		fd:   f,
		path: fmt.Sprintf("/proc/self/fd/%d", fd),
	}, nil
}

// CreateCloexec returns a new SecureFile backed by memfd with
// MFD_CLOEXEC set. The fd is NOT inherited by child processes.
// Use for core-only consumers (TLS cert/key, OAuth2 credentials).
func CreateCloexec(name string) (*SecureFile, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	f := os.NewFile(uintptr(fd), name)
	return &SecureFile{
		fd:   f,
		path: fmt.Sprintf("/proc/self/fd/%d", fd),
	}, nil
}
