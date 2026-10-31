package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"time"
)

//go:embed migrations/*.sql
var embeddedFS embed.FS

// embedded is the built-in migration set.
var embedded = mustSub(embeddedFS, "migrations")

func mustSub(f fs.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return sub
}

// migrationName is NNNN_description.sql.
var migrationName = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

type migration struct {
	version  int
	name     string
	sql      string
	checksum string
}

// loadMigrations reads and orders the migrations in f. Versions must start at
// 1 and have no gaps, so a missing file can't go unnoticed.
func loadMigrations(f fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(f, ".")
	if err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}
	var ms []migration
	for _, e := range entries {
		m := migrationName.FindStringSubmatch(e.Name())
		if e.IsDir() || m == nil {
			return nil, fmt.Errorf("migrations: unexpected file %q (want NNNN_name.sql)", e.Name())
		}
		version, _ := strconv.Atoi(m[1])
		body, err := fs.ReadFile(f, path.Clean(e.Name()))
		if err != nil {
			return nil, fmt.Errorf("migrations: %w", err)
		}
		sum := sha256.Sum256(body)
		ms = append(ms, migration{version: version, name: e.Name(), sql: string(body), checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("migrations: expected version %04d, found %s", i+1, m.name)
		}
	}
	return ms, nil
}

const createMigrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
	version    INTEGER PRIMARY KEY,
	name       TEXT NOT NULL,
	checksum   TEXT NOT NULL,
	applied_at TEXT NOT NULL
) STRICT`

// migrate applies pending migrations, each in its own transaction with its
// schema_migrations row, so a failed migration leaves no trace. It refuses a
// database that is newer than this binary, or whose applied migrations no
// longer match the files.
func migrate(ctx context.Context, db *sql.DB, f fs.FS) error {
	ms, err := loadMigrations(f)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, createMigrationsTable); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}

	applied := map[int]string{}
	rows, err := db.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations ORDER BY version`)
	if err != nil {
		return fmt.Errorf("migrations: %w", err)
	}
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			_ = rows.Close()
			return fmt.Errorf("migrations: %w", err)
		}
		applied[v] = sum
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return fmt.Errorf("migrations: %w", err)
	}

	for v := range applied {
		if v > len(ms) {
			return fmt.Errorf("database schema is version %d, newer than this valetd (%d); upgrade valetd", maxKey(applied), len(ms))
		}
	}
	for _, m := range ms {
		sum, done := applied[m.version]
		if done {
			if sum != m.checksum {
				return fmt.Errorf("migration %s changed after it was applied", m.name)
			}
			continue
		}
		if err := apply(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

func apply(ctx context.Context, db *sql.DB, m migration) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migration %s: %w", m.name, err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("migration %s: %w", m.name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (version, name, checksum, applied_at) VALUES (?, ?, ?, ?)`,
		m.version, m.name, m.checksum, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("migration %s: %w", m.name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migration %s: %w", m.name, err)
	}
	return nil
}

func maxKey(m map[int]string) int {
	n := 0
	for k := range m {
		n = max(n, k)
	}
	return n
}
