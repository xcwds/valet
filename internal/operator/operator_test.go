package operator

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/store"
	"github.com/xcwds/valet/internal/tokens"
)

var ctx = context.Background()

func newService(t *testing.T) (*Service, string, *store.Store) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	db, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewService(db, audit.New(db, logging.New(&bytes.Buffer{}, "json", slog.LevelError))), dir, db
}

func readToken(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestBootstrapOnce(t *testing.T) {
	s, dir, _ := newService(t)
	path, err := s.Bootstrap(ctx, dir)
	if err != nil || path != filepath.Join(dir, TokenFile) {
		t.Fatalf("Bootstrap = %q, %v", path, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %#o", info.Mode().Perm())
	}
	tok := readToken(t, path)
	if _, err := tokens.Parse(tokens.Admin, tok); err != nil {
		t.Fatalf("file holds %q", tok)
	}
	if name, err := s.Authenticate(ctx, tok); err != nil || name != "bootstrap" {
		t.Fatalf("Authenticate = %q, %v", name, err)
	}
	again, err := s.Bootstrap(ctx, dir)
	if err != nil || again != "" {
		t.Fatalf("second Bootstrap = %q, %v; want no new token", again, err)
	}
	if readToken(t, path) != tok {
		t.Fatal("the token file changed")
	}
	if _, err := os.Stat(path + ".new"); !errors.Is(err, os.ErrNotExist) {
		t.Error("temporary file left behind")
	}
}

func TestAuthenticateFailures(t *testing.T) {
	s, dir, _ := newService(t)
	if _, err := s.Bootstrap(ctx, dir); err != nil {
		t.Fatal(err)
	}
	sess, _, _ := tokens.New(tokens.Session)
	other, _, _ := tokens.New(tokens.Admin)
	for _, tok := range []string{"", "nope", sess, other} {
		if _, err := s.Authenticate(ctx, tok); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("Authenticate(%.15q) = %v", tok, err)
		}
	}
}

func TestReset(t *testing.T) {
	s, dir, db := newService(t)
	path, _ := s.Bootstrap(ctx, dir)
	old := readToken(t, path)
	if _, err := s.Reset(ctx, dir); err != nil {
		t.Fatal(err)
	}
	fresh := readToken(t, path)
	if fresh == old {
		t.Fatal("reset kept the old token")
	}
	if _, err := s.Authenticate(ctx, old); !errors.Is(err, ErrUnauthenticated) {
		t.Error("old token still works after reset")
	}
	if _, err := s.Authenticate(ctx, fresh); err != nil {
		t.Errorf("new token: %v", err)
	}
	recs, _ := audit.Tail(ctx, db.Read(), audit.Filter{Limit: 100})
	var creates int
	for _, r := range recs {
		if r.Action == "admin_token.create" {
			creates++
			if strings.Contains(string(r.Params), "vlt_admin_") {
				t.Error("token in the audit record")
			}
		}
	}
	if creates != 2 {
		t.Errorf("%d admin_token.create records, want 2", creates)
	}
}
