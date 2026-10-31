//go:build !unix

package store

import (
	"fmt"
	"os"
)

// lockDir only creates the lock file where flock isn't available; Valet's
// supported platforms are Unix (RFC Deployment).
func lockDir(dataDir string) (*os.File, error) {
	f, err := os.OpenFile(lockPath(dataDir), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: lock: %w", err)
	}
	return f, nil
}
