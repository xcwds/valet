package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func openT(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func tables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	return names
}

func versions(t *testing.T, db *sql.DB) []int {
	t.Helper()
	rows, err := db.Query(`SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var vs []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		vs = append(vs, v)
	}
	return vs
}

func TestFreshDatabase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s := openT(t, dir)

	if _, err := os.Stat(filepath.Join(dir, LockName)); err != nil {
		t.Errorf("lock file: %v", err)
	}
	got := strings.Join(tables(t, s.Read()), ",")
	if want := "admin_tokens,audit_events,enrollments,jobs,master_keys,schema_migrations,secrets,sessions"; got != want {
		t.Errorf("tables = %s, want %s", got, want)
	}
	if vs := versions(t, s.Read()); len(vs) != builtinCount(t) || vs[0] != 1 {
		t.Errorf("versions = %v, want 1..%d", vs, builtinCount(t))
	}
	var mode string
	if err := s.Read().QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Errorf("journal_mode = %q (%v), want wal", mode, err)
	}
}

func TestPrivateModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permission bits")
	}
	dir := filepath.Join(t.TempDir(), "data")
	s := openT(t, dir)
	// Force the WAL and shared-memory files into existence.
	if err := s.Write(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO jobs VALUES ('j', 'r', '{}', 'agent/j/*', 60, 't', 'active', 'op', 't', NULL)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	check := func(path string, want os.FileMode) {
		t.Helper()
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s mode = %#o, want %#o", filepath.Base(path), got, want)
		}
	}
	check(dir, 0o700)
	check(s.Path(), 0o600)
	check(s.Path()+"-wal", 0o600)
	check(s.Path()+"-shm", 0o600)
}

func TestRefusesPermissivePaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no Unix permission bits")
	}
	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		_, err := Open(context.Background(), dir)
		if err == nil || !strings.Contains(err.Error(), "chmod 700") {
			t.Fatalf("err = %v, want a refusal naming chmod 700", err)
		}
	})
	t.Run("database file", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "data")
		openT(t, dir).Close()
		if err := os.Chmod(filepath.Join(dir, FileName), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Open(context.Background(), dir)
		if err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("err = %v, want a refusal naming chmod 600", err)
		}
	})
}

func TestReopenIsNoOp(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s := openT(t, dir)
	var before string
	if err := s.Read().QueryRow(`SELECT applied_at FROM schema_migrations WHERE version = 1`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = openT(t, dir)
	var after string
	if err := s.Read().QueryRow(`SELECT applied_at FROM schema_migrations WHERE version = 1`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Errorf("migration 1 re-applied: %s then %s", before, after)
	}
	if vs := versions(t, s.Read()); len(vs) != builtinCount(t) {
		t.Errorf("versions = %v", vs)
	}
}

func builtinCount(t *testing.T) int {
	t.Helper()
	ms, err := loadMigrations(embedded)
	if err != nil {
		t.Fatal(err)
	}
	return len(ms)
}

func TestRefusesNewerDatabase(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s := openT(t, dir)
	if err := s.Write(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO schema_migrations VALUES (99, '0099_future.sql', 'x', 't')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	_, err := Open(context.Background(), dir)
	if err == nil || !strings.Contains(err.Error(), "newer than this valetd") {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

func openFS(t *testing.T, dir string, f fstest.MapFS) (*Store, error) {
	t.Helper()
	s, err := open(context.Background(), dir, f)
	if s != nil {
		t.Cleanup(func() { _ = s.Close() })
	}
	return s, err
}

func TestFailedMigrationRollsBack(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	good := &fstest.MapFile{Data: []byte(`CREATE TABLE a (x INTEGER) STRICT;`)}
	// The first statement succeeds, the second fails: neither may stick.
	bad := &fstest.MapFile{Data: []byte(`CREATE TABLE b (x INTEGER) STRICT; INSERT INTO missing VALUES (1);`)}

	_, err := openFS(t, dir, fstest.MapFS{"0001_a.sql": good, "0002_b.sql": bad})
	if err == nil || !strings.Contains(err.Error(), "0002_b.sql") {
		t.Fatalf("err = %v, want migration 0002 to fail", err)
	}

	s, err := openFS(t, dir, fstest.MapFS{"0001_a.sql": good})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(tables(t, s.Read()), ","); got != "a,schema_migrations" {
		t.Errorf("tables = %s; table b from the failed migration survived", got)
	}
	if vs := versions(t, s.Read()); len(vs) != 1 {
		t.Errorf("versions = %v, want only 1 recorded", vs)
	}
	s.Close()

	fixed := &fstest.MapFile{Data: []byte(`CREATE TABLE b (x INTEGER) STRICT;`)}
	s, err = openFS(t, dir, fstest.MapFS{"0001_a.sql": good, "0002_b.sql": fixed})
	if err != nil {
		t.Fatalf("fixed migration did not apply: %v", err)
	}
	if vs := versions(t, s.Read()); len(vs) != 2 {
		t.Errorf("versions = %v, want [1 2]", vs)
	}
}

func TestRefusesChangedMigration(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s, err := openFS(t, dir, fstest.MapFS{"0001_a.sql": {Data: []byte(`CREATE TABLE a (x INTEGER);`)}})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	_, err = openFS(t, dir, fstest.MapFS{"0001_a.sql": {Data: []byte(`CREATE TABLE a (x TEXT);`)}})
	if err == nil || !strings.Contains(err.Error(), "changed after it was applied") {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

func TestBadMigrationSets(t *testing.T) {
	sql := &fstest.MapFile{Data: []byte(`SELECT 1;`)}
	tests := map[string]fstest.MapFS{
		"gap":        {"0001_a.sql": sql, "0003_c.sql": sql},
		"no first":   {"0002_b.sql": sql},
		"bad name":   {"0001_a.sql": sql, "2_b.sql": sql},
		"stray file": {"0001_a.sql": sql, "README.md": sql},
		"duplicate":  {"0001_a.sql": sql, "0001_b.sql": sql},
	}
	for name, f := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := openFS(t, filepath.Join(t.TempDir(), "data"), f); err == nil {
				t.Fatal("opened with a broken migration set")
			}
		})
	}
}

func TestReadPoolIsReadOnly(t *testing.T) {
	s := openT(t, filepath.Join(t.TempDir(), "data"))
	_, err := s.Read().Exec(`INSERT INTO jobs VALUES ('j', 'r', '{}', 'p', 60, 't', 'active', 'op', 't', NULL)`)
	if err == nil {
		t.Fatal("write through the read pool succeeded")
	}
}

func TestWriteRollsBackOnError(t *testing.T) {
	s := openT(t, filepath.Join(t.TempDir(), "data"))
	boom := errors.New("boom")
	err := s.Write(context.Background(), func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO jobs VALUES ('j', 'r', '{}', 'p', 60, 't', 'active', 'op', 't', NULL)`); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want boom", err)
	}
	var n int
	if err := s.Read().QueryRow(`SELECT count(*) FROM jobs`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("jobs = %d (%v), want the insert rolled back", n, err)
	}
}

func TestConcurrentWrites(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s, err := openFS(t, dir, fstest.MapFS{"0001_t.sql": {Data: []byte(`CREATE TABLE t (n INTEGER) STRICT;`)}})
	if err != nil {
		t.Fatal(err)
	}

	const writers, each = 20, 25
	var wg sync.WaitGroup
	errc := make(chan error, writers*each)
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if err := s.Write(context.Background(), func(tx *sql.Tx) error {
					_, err := tx.Exec(`INSERT INTO t VALUES (?)`, w*each+i)
					return err
				}); err != nil {
					errc <- err
				}
				// Readers run alongside the writer.
				var n int
				if err := s.Read().QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil {
					errc <- fmt.Errorf("read: %w", err)
				}
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Error(err)
	}
	var n int
	if err := s.Read().QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil || n != writers*each {
		t.Fatalf("rows = %d (%v), want %d", n, err, writers*each)
	}
}

func TestSchemaGuards(t *testing.T) {
	s := openT(t, filepath.Join(t.TempDir(), "data"))
	exec := func(q string) error {
		return s.Write(context.Background(), func(tx *sql.Tx) error {
			_, err := tx.Exec(q)
			return err
		})
	}

	if err := exec(`INSERT INTO sessions VALUES ('s', 'no-such-job', x'00', 't', NULL)`); err == nil {
		t.Error("session for a missing job was accepted; foreign keys are off")
	}
	if err := exec(`INSERT INTO jobs VALUES ('j', 'r', '{}', 'p', 60, 't', 'paused', 'op', 't', NULL)`); err == nil {
		t.Error("job with an unknown state was accepted")
	}
	if err := exec(`INSERT INTO audit_events VALUES (1, 't', NULL, NULL, 'cli', 'job.create', '{}', 'allow', NULL, NULL, NULL, x'00', x'01')`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE audit_events SET decision = 'deny'`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("audit update: err = %v, want append-only refusal", err)
	}
	if err := exec(`DELETE FROM audit_events`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("audit delete: err = %v, want append-only refusal", err)
	}
}

func TestPing(t *testing.T) {
	s := openT(t, filepath.Join(t.TempDir(), "data"))
	if err := s.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("Ping succeeded on a closed store")
	}
}

func TestPanicInWriteRollsBack(t *testing.T) {
	s := openT(t, filepath.Join(t.TempDir(), "data"))
	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic was swallowed")
			}
		}()
		_ = s.Write(context.Background(), func(tx *sql.Tx) error {
			if _, err := tx.Exec(`INSERT INTO jobs VALUES ('j', 'r', '{}', 'p', 60, 't', 'active', 'op', 't', NULL)`); err != nil {
				t.Fatal(err)
			}
			panic("boom")
		})
	}()

	// The writer must be free again, and the insert gone.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO jobs VALUES ('k', 'r', '{}', 'p', 60, 't', 'active', 'op', 't', NULL)`)
		return err
	}); err != nil {
		t.Fatalf("write after a panic: %v (writer left in a transaction?)", err)
	}
	var n int
	if err := s.Read().QueryRow(`SELECT count(*) FROM jobs WHERE id = 'j'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("panicked insert kept: %d (%v)", n, err)
	}
}

func TestOneValetdPerDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock is Unix-only")
	}
	dir := filepath.Join(t.TempDir(), "data")
	s := openT(t, dir)

	_, err := Open(context.Background(), dir)
	if err == nil || !strings.Contains(err.Error(), "in use by another valetd") {
		t.Fatalf("second Open: err = %v, want it refused", err)
	}

	// Closing releases the lock.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	_ = s2.Close()
}

func TestOpenReadOnlyWhileOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	s := openT(t, dir)
	if err := s.Write(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(`INSERT INTO jobs VALUES ('j', 'r', '{}', 'p', 60, 't', 'active', 'op', 't', NULL)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	ro, err := OpenReadOnly(context.Background(), dir)
	if err != nil {
		t.Fatalf("read-only open while the store holds the lock: %v", err)
	}
	defer ro.Close()
	var n int
	if err := ro.QueryRow(`SELECT count(*) FROM jobs`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("count = %d (%v)", n, err)
	}
	if _, err := ro.Exec(`DELETE FROM jobs`); err == nil {
		t.Fatal("write through the read-only handle succeeded")
	}
}

func TestOpenReadOnlyMissing(t *testing.T) {
	if _, err := OpenReadOnly(context.Background(), filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("opened a database that doesn't exist")
	}
}
