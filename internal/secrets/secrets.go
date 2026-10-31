// Package secrets is Hekate, Valet's secret store (RFC decision 1).
//
// Upstream credentials are kept envelope-encrypted in the database: each
// secret has its own random AES-256 data key, which encrypts the value with
// AES-GCM; the master key wraps the data key, also with AES-GCM. The secret's
// name is bound into both as additional data, so a ciphertext copied to
// another row fails to decrypt. Neither the master key nor any plaintext is
// ever written to the database.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/store"
)

// MaxSecretSize bounds a secret value. Upstream credentials (tokens, PEM
// keys) are far smaller.
const MaxSecretSize = 64 << 10

// ErrNotFound is returned for a secret that doesn't exist.
var ErrNotFound = errors.New("secret not found")

// validName keeps names to a safe, printable set: they appear in configs,
// logs and audit rows.
var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,127}$`)

// ValidateName reports whether name may be used for a secret. Names appear in
// URL paths, so path-like tricks (.. segments, empty segments, a trailing /)
// are refused.
func ValidateName(name string) error {
	if !validName.MatchString(name) || strings.HasSuffix(name, "/") || strings.Contains(name, "//") ||
		slices.Contains(strings.Split(name, "/"), "..") || slices.Contains(strings.Split(name, "/"), ".") {
		return fmt.Errorf("secret name %q: use 1-128 of a-z 0-9 . _ / -, starting with a letter or digit, with no empty, . or .. segments", name)
	}
	return nil
}

// Additional data for each GCM use. Distinct prefixes keep a wrapped key, a
// value and the canary from ever being valid in each other's place.
const (
	adValue  = "valet/secret/value/v1\x00"
	adKey    = "valet/secret/data-key/v1\x00"
	adCanary = "valet/master-key/canary/v1"
)

// Store reads and writes secrets.
type Store struct {
	db    *store.Store
	key   *MasterKey
	gcm   cipher.AEAD // master key
	audit *audit.Log
	now   func() time.Time
}

// Open checks master against the database and returns the secret store. The
// first key used with a database is recorded with a canary; afterwards a
// different key, or one that fails to decrypt its canary, is refused before
// any secret is touched. The outcome is audited either way; puts and deletes
// are audited in the same transaction as the change, by name only.
func Open(ctx context.Context, db *store.Store, master *MasterKey, log *audit.Log) (*Store, error) {
	gcm, err := newGCM(master.key.Reveal())
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, key: master, gcm: gcm, audit: log, now: time.Now}
	if err := s.checkCanary(ctx); err != nil {
		// Record the refusal in its own transaction; the check's rolled back.
		if _, aerr := log.Append(ctx, audit.Event{
			Interface: audit.InterfaceSystem, Action: "master_key.verify", Decision: audit.Deny,
			Params: map[string]any{"key_id": master.ID()}, Error: err.Error(),
		}); aerr != nil {
			return nil, errors.Join(err, aerr)
		}
		return nil, err
	}
	return s, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	return gcm, nil
}

// seal encrypts plaintext with a fresh random nonce, returned prepended.
func seal(gcm cipher.AEAD, plaintext []byte, ad string) ([]byte, error) {
	nonce := make([]byte, gcm.NonceSize(), gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, []byte(ad)), nil
}

func open(gcm cipher.AEAD, sealed []byte, ad string) ([]byte, error) {
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, []byte(ad))
}

func (s *Store) checkCanary(ctx context.Context) error {
	var rec audit.Record
	err := s.db.Write(ctx, func(tx *sql.Tx) (err error) {
		action := "master_key.verify"
		defer func() {
			if err == nil {
				rec, err = s.audit.AppendTx(ctx, tx, audit.Event{
					Interface: audit.InterfaceSystem, Action: action, Decision: audit.Allow,
					Params: map[string]any{"key_id": s.key.ID()},
				})
			}
		}()
		var canary []byte
		err = tx.QueryRowContext(ctx, `SELECT canary FROM master_keys WHERE key_id = ?`, s.key.ID()).Scan(&canary)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			var others int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM master_keys`).Scan(&others); err != nil {
				return fmt.Errorf("secrets: %w", err)
			}
			if others > 0 {
				return errors.New("secrets: the master key does not match this database (wrong key, or the key was replaced)")
			}
			// First start with this database: record the key.
			action = "master_key.record"
			c, err := seal(s.gcm, []byte(adCanary), adCanary)
			if err != nil {
				return fmt.Errorf("secrets: %w", err)
			}
			_, err = tx.ExecContext(ctx, `INSERT INTO master_keys (key_id, canary, created_at) VALUES (?, ?, ?)`,
				s.key.ID(), c, s.timestamp())
			if err != nil {
				return fmt.Errorf("secrets: %w", err)
			}
			return nil
		case err != nil:
			return fmt.Errorf("secrets: %w", err)
		}
		if _, err := open(s.gcm, canary, adCanary); err != nil {
			return errors.New("secrets: the master key failed to decrypt its canary; the key or the database is corrupt")
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.audit.Emit(ctx, rec)
	return nil
}

func (s *Store) timestamp() string { return s.now().UTC().Format(time.RFC3339Nano) }

// Put stores value under name, replacing any existing value.
func (s *Store) Put(ctx context.Context, name string, value []byte) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if len(value) == 0 {
		return errors.New("secrets: empty value")
	}
	if len(value) > MaxSecretSize {
		return fmt.Errorf("secrets: value is %d bytes, more than %d", len(value), MaxSecretSize)
	}

	dataKey := make([]byte, KeySize)
	defer clear(dataKey)
	if _, err := rand.Read(dataKey); err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	dek, err := newGCM(dataKey)
	if err != nil {
		return err
	}
	ciphertext, err := seal(dek, value, adValue+name)
	if err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	wrapped, err := seal(s.gcm, dataKey, adKey+name)
	if err != nil {
		return fmt.Errorf("secrets: %w", err)
	}
	// The value's nonce is stored on its own to match the schema; ciphertext
	// holds the rest.
	nonce, body := ciphertext[:dek.NonceSize()], ciphertext[dek.NonceSize():]

	now := s.timestamp()
	var rec audit.Record
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO secrets (name, key_id, wrapped_key, nonce, ciphertext, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (name) DO UPDATE SET
				key_id = excluded.key_id, wrapped_key = excluded.wrapped_key,
				nonce = excluded.nonce, ciphertext = excluded.ciphertext,
				updated_at = excluded.updated_at`,
			name, s.key.ID(), wrapped, nonce, body, now, now)
		if err != nil {
			return fmt.Errorf("secrets: put %s: %w", name, err)
		}
		rec, err = s.audit.AppendTx(ctx, tx, audit.Event{
			Interface: audit.InterfaceAdmin, Action: "secret.put", Decision: audit.Allow,
			Params: map[string]any{"name": name, "length": len(value)},
		})
		return err
	})
	if err != nil {
		return err
	}
	s.audit.Emit(ctx, rec)
	return nil
}

// Get returns the secret stored under name.
func (s *Store) Get(ctx context.Context, name string) (Secret, error) {
	if err := ValidateName(name); err != nil {
		return Secret{}, err
	}
	var keyID string
	var wrapped, nonce, body []byte
	err := s.db.Read().QueryRowContext(ctx,
		`SELECT key_id, wrapped_key, nonce, ciphertext FROM secrets WHERE name = ?`, name).
		Scan(&keyID, &wrapped, &nonce, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return Secret{}, fmt.Errorf("secrets: %s: %w", name, ErrNotFound)
	}
	if err != nil {
		return Secret{}, fmt.Errorf("secrets: get %s: %w", name, err)
	}
	if keyID != s.key.ID() {
		return Secret{}, fmt.Errorf("secrets: %s is wrapped by master key %s, not the current one", name, keyID)
	}

	dataKey, err := open(s.gcm, wrapped, adKey+name)
	if err != nil {
		return Secret{}, fmt.Errorf("secrets: %s: data key failed to decrypt (tampered or moved row)", name)
	}
	defer clear(dataKey)
	dek, err := newGCM(dataKey)
	if err != nil {
		return Secret{}, err
	}
	value, err := open(dek, append(nonce, body...), adValue+name)
	if err != nil {
		return Secret{}, fmt.Errorf("secrets: %s: value failed to decrypt (tampered or moved row)", name)
	}
	return NewSecret(value), nil
}

// Delete removes the secret stored under name.
func (s *Store) Delete(ctx context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	var rec audit.Record
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM secrets WHERE name = ?`, name)
		if err != nil {
			return fmt.Errorf("secrets: delete %s: %w", name, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("secrets: %s: %w", name, ErrNotFound)
		}
		rec, err = s.audit.AppendTx(ctx, tx, audit.Event{
			Interface: audit.InterfaceAdmin, Action: "secret.delete", Decision: audit.Allow,
			Params: map[string]any{"name": name},
		})
		return err
	})
	if err != nil {
		return err
	}
	s.audit.Emit(ctx, rec)
	return nil
}

// Info describes a stored secret without its value.
type Info struct {
	Name      string
	UpdatedAt string
}

// List returns every secret's name and last update, sorted by name.
func (s *Store) List(ctx context.Context) ([]Info, error) {
	rows, err := s.db.Read().QueryContext(ctx, `SELECT name, updated_at FROM secrets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("secrets: list: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Info
	for rows.Next() {
		var i Info
		if err := rows.Scan(&i.Name, &i.UpdatedAt); err != nil {
			return nil, fmt.Errorf("secrets: list: %w", err)
		}
		out = append(out, i)
	}
	return out, rows.Err()
}
