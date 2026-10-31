// Package operator authenticates the people who run Valet.
//
// The admin API (port 14400) accepts only admin tokens (vlt_admin_…), stored
// as SHA-256 hashes in admin_tokens. On first start valetd creates one and
// writes it to data_dir/admin.token (mode 0600), where the CLI on the same
// host finds it; the token is never logged or printed by valetd.
package operator

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/store"
	"github.com/xcwds/valet/internal/tokens"
)

// TokenFile is the bootstrap token's name inside the data directory.
const TokenFile = "admin.token"

// ErrUnauthenticated covers every way an admin token can fail.
var ErrUnauthenticated = errors.New("unauthenticated")

// Service manages and checks admin tokens.
type Service struct {
	db    *store.Store
	audit *audit.Log
	now   func() time.Time
}

// NewService returns a Service.
func NewService(db *store.Store, log *audit.Log) *Service {
	return &Service{db: db, audit: log, now: time.Now}
}

func newID() (string, error) {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "adm-" + strings.ToLower(base32.StdEncoding.EncodeToString(b)), nil
}

// Bootstrap makes sure an operator can get in: if no admin token is active,
// it creates one and writes it to dataDir/admin.token. It returns the file's
// path when it created a token, and "" when one already existed.
func (s *Service) Bootstrap(ctx context.Context, dataDir string) (string, error) {
	var active int
	if err := s.db.Read().QueryRowContext(ctx,
		`SELECT count(*) FROM admin_tokens WHERE revoked_at IS NULL`).Scan(&active); err != nil {
		return "", fmt.Errorf("operator: %w", err)
	}
	if active > 0 {
		return "", nil
	}
	return s.issue(ctx, dataDir, "bootstrap", false)
}

// Reset revokes every admin token and writes a new one, for an operator who
// lost theirs. It needs the data directory lock, so valetd must be stopped.
func (s *Service) Reset(ctx context.Context, dataDir string) (string, error) {
	return s.issue(ctx, dataDir, "reset", true)
}

// issue writes the new token to a temporary file first, commits the hash and
// its audit record, then renames the file into place. A failure at any step
// leaves no token in the database without a file, which would lock the
// operator out.
func (s *Service) issue(ctx context.Context, dataDir, name string, revokeOthers bool) (string, error) {
	token, hash, err := tokens.New(tokens.Admin)
	if err != nil {
		return "", err
	}
	id, err := newID()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dataDir, TokenFile)
	tmp := path + ".new"
	_ = os.Remove(tmp)
	if err := writeExclusive(tmp, []byte(token+"\n")); err != nil {
		return "", fmt.Errorf("operator: %w", err)
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	var rec audit.Record
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		var revoked int64
		if revokeOthers {
			res, err := tx.ExecContext(ctx, `UPDATE admin_tokens SET revoked_at = ? WHERE revoked_at IS NULL`, now)
			if err != nil {
				return err
			}
			revoked, _ = res.RowsAffected()
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO admin_tokens (id, name, token_hash, created_at) VALUES (?, ?, ?, ?)`,
			id, name, hash, now); err != nil {
			return err
		}
		rec, err = s.audit.AppendTx(ctx, tx, audit.Event{
			Interface: audit.InterfaceSystem, Action: "admin_token.create", Decision: audit.Allow,
			Params: map[string]any{"id": id, "name": name, "revoked_others": revoked},
		})
		return err
	})
	if err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("operator: %w", err)
	}
	s.audit.Emit(ctx, rec)
	if err := os.Rename(tmp, path); err != nil {
		return "", fmt.Errorf("operator: the new admin token is in %s but could not be moved to %s: %w", tmp, path, err)
	}
	return path, nil
}

func writeExclusive(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // data_dir plus a constant.
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// Authenticate checks an admin token and returns the token's name. Every
// failure returns ErrUnauthenticated and is audited with the reason.
func (s *Service) Authenticate(ctx context.Context, token string) (string, error) {
	name, reason, err := s.authenticate(ctx, token)
	if err == nil {
		return name, nil
	}
	if reason == "" {
		return "", err
	}
	if _, aerr := s.audit.Append(ctx, audit.Event{
		Interface: audit.InterfaceAdmin, Action: "admin.authenticate", Decision: audit.Deny,
		Params: map[string]any{"reason": reason},
	}); aerr != nil {
		return "", errors.Join(ErrUnauthenticated, aerr)
	}
	return "", ErrUnauthenticated
}

func (s *Service) authenticate(ctx context.Context, token string) (string, string, error) {
	if token == "" {
		return "", "missing token", ErrUnauthenticated
	}
	hash, err := tokens.Parse(tokens.Admin, token)
	if err != nil {
		return "", "malformed token", ErrUnauthenticated
	}
	var name string
	var stored []byte
	var revoked sql.NullString
	err = s.db.Read().QueryRowContext(ctx,
		`SELECT name, token_hash, revoked_at FROM admin_tokens WHERE token_hash = ?`, hash).
		Scan(&name, &stored, &revoked)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && subtle.ConstantTimeCompare(stored, hash) != 1) {
		return "", "unknown token", ErrUnauthenticated
	}
	if err != nil {
		return "", "", fmt.Errorf("operator: authenticate: %w", err)
	}
	if revoked.Valid {
		return "", "revoked token", ErrUnauthenticated
	}
	return name, "", nil
}
