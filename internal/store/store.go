// Package store is valetd's persistence: one SQLite database in the data
// directory, opened with modernc.org/sqlite (no cgo; RFC Tech stack).
//
// Writes go through a single connection (SQLite serializes writers anyway, and
// one connection with BEGIN IMMEDIATE avoids SQLITE_BUSY under load). Reads use
// a separate read-only pool, which WAL lets run alongside the writer.
//
// The database file and data directory are private to valetd: 0600 and 0700.
// Open refuses to use either if group or others can access it.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// FileName is the database's name inside the data directory.
const FileName = "valet.db"

// LockName is the file valetd locks so only one process uses a data directory.
const LockName = "valetd.lock"

func lockPath(dataDir string) string { return filepath.Join(dataDir, LockName) }

// Store holds the database's writer and reader pools.
type Store struct {
	path   string
	lock   *os.File
	writer *sql.DB
	reader *sql.DB
}

// Open opens (creating if needed) the database in dataDir and applies any
// pending migrations from the built-in set.
func Open(ctx context.Context, dataDir string) (*Store, error) {
	return open(ctx, dataDir, embedded)
}

func open(ctx context.Context, dataDir string, migrations fs.FS) (*Store, error) {
	if err := privateDir(dataDir); err != nil {
		return nil, err
	}
	// One valetd per data directory: the single writer the audit chain
	// relies on must really be single, and migrations must not race.
	lock, err := lockDir(dataDir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, FileName)
	if err := privateFile(path); err != nil {
		_ = lock.Close()
		return nil, err
	}

	writer, err := sql.Open("sqlite", dsn(path, false))
	if err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	writer.SetMaxOpenConns(1)
	writer.SetMaxIdleConns(1)
	writer.SetConnMaxLifetime(0)

	reader, err := sql.Open("sqlite", dsn(path, true))
	if err != nil {
		_ = writer.Close()
		_ = lock.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	reader.SetMaxOpenConns(max(4, runtime.NumCPU()))

	s := &Store{path: path, lock: lock, writer: writer, reader: reader}
	if err := writer.PingContext(ctx); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := migrate(ctx, writer, migrations); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("store: %s: %w", path, err)
	}
	return s, nil
}

// dsn builds the modernc.org/sqlite connection string. Every connection gets
// the same pragmas; readers are additionally query-only.
func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)") // the audit chain must survive power loss
	q.Set("_txlock", "immediate")
	q.Set("_time_format", "sqlite")
	if readOnly {
		q.Add("_pragma", "query_only(1)")
	}
	return (&url.URL{Scheme: "file", OmitHost: true, Path: path, RawQuery: q.Encode()}).String()
}

// Path is the database file's path.
func (s *Store) Path() string { return s.path }

// Read returns the read-only pool. Writes through it fail.
func (s *Store) Read() *sql.DB { return s.reader }

// Write runs fn in a write transaction (BEGIN IMMEDIATE on the single writer
// connection) and commits if fn returns nil. An error or a panic in fn rolls
// back, so the writer connection is never left inside a transaction.
func (s *Store) Write(ctx context.Context, fn func(*sql.Tx) error) (err error) {
	tx, err := s.writer.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// Ping checks that the database answers a read.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.reader.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

// Close closes both pools, then releases the data directory lock.
func (s *Store) Close() error {
	return errors.Join(s.reader.Close(), s.writer.Close(), s.lock.Close())
}

// privateDir creates dir with mode 0700, or checks an existing one isn't open
// to group or others.
func privateDir(dir string) error {
	if dir == "" {
		return errors.New("store: data directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store: data directory: %w", err)
	}
	return checkPrivate(dir, "data directory", "chmod 700")
}

// privateFile creates the database file with mode 0600 before SQLite opens it
// (SQLite would create it with the umask's mode), or checks an existing one.
// SQLite gives the -wal and -shm files the database file's mode.
func privateFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // path is the operator's data_dir plus a constant.
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("store: %w", err)
	}
	return checkPrivate(path, "database file", "chmod 600")
}

func checkPrivate(path, what, fix string) error {
	if runtime.GOOS == "windows" {
		return nil // no Unix permission bits to check
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("store: %s: %w", what, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("store: %s %s has mode %#o, readable by others; run: %s %s", what, path, perm, fix, path)
	}
	return nil
}
