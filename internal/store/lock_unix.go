//go:build unix

package store

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// lockDir takes an exclusive, non-blocking flock on dataDir/LockName so only
// one valetd uses a data directory. The kernel drops the lock if the process
// dies, so a crash never leaves a stale lock behind.
func lockDir(dataDir string) (*os.File, error) {
	path := lockPath(dataDir)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // data_dir plus a constant.
	if err != nil {
		return nil, fmt.Errorf("store: lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // Fd fits in an int on every unix.
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("store: %s is in use by another valetd (lock %s held)", dataDir, path)
		}
		return nil, fmt.Errorf("store: lock %s: %w", path, err)
	}
	return f, nil
}
