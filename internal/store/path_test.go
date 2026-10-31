package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOddPaths(t *testing.T) {
	for _, name := range []string{"has space", "hash#mark", "q?mark", "pct%41", "amp&x=y"} {
		dir := filepath.Join(t.TempDir(), name)
		s, err := Open(context.Background(), dir)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		s.Close()
		if _, err := os.Stat(filepath.Join(dir, FileName)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		entries, _ := os.ReadDir(filepath.Dir(dir))
		for _, e := range entries {
			if e.Name() != name {
				t.Errorf("%s: stray entry %q", name, e.Name())
			}
		}
	}
}
