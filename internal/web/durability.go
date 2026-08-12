package web

import (
	"fmt"
	"os"
	"path/filepath"
)

// fsyncParentDir makes a successful rename or unlink durable across a Linux
// crash. Syncing the file alone does not commit the parent directory entry.
func fsyncParentDir(path string) error {
	dir := filepath.Dir(path)
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open parent directory %s: %w", dir, err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync parent directory %s: %w", dir, err)
	}
	return nil
}
