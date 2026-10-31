package secrets

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/store"
)

func newKey(t *testing.T) *MasterKey {
	t.Helper()
	enc, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseMasterKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fixture opens a store in a fresh data dir with a fresh key.
type fixture struct {
	dir string
	db  *store.Store
	key *MasterKey
	s   *Store
	out *bytes.Buffer // audit stream
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{dir: filepath.Join(t.TempDir(), "data"), key: newKey(t)}
	f.reopen(t, f.key)
	return f
}

func (f *fixture) reopen(t *testing.T, key *MasterKey) error {
	t.Helper()
	if f.db != nil {
		_ = f.db.Close()
	}
	db, err := store.Open(context.Background(), f.dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f.db = db
	f.out = &bytes.Buffer{}
	s, err := Open(context.Background(), db, key, audit.New(db, logging.New(f.out, "json", slog.LevelError)))
	f.s = s
	return err
}

func (f *fixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	if err := f.db.Write(context.Background(), func(tx *sql.Tx) error {
		_, err := tx.Exec(q, args...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// flipByte inverts one byte of a secret's column; i < 0 counts from the end.
func (f *fixture) flipByte(t *testing.T, col, name string, i int) {
	t.Helper()
	var b []byte
	if err := f.db.Read().QueryRow(`SELECT `+col+` FROM secrets WHERE name = ?`, name).Scan(&b); err != nil {
		t.Fatal(err)
	}
	if i < 0 {
		i += len(b)
	}
	b[i] ^= 0xFF
	f.exec(t, `UPDATE secrets SET `+col+` = ? WHERE name = ?`, b, name)
}

var ctx = context.Background()

func TestRoundTrip(t *testing.T) {
	f := newFixture(t)
	value := []byte("ghp_not-a-real-token-but-shaped-like-one")
	if err := f.s.Put(ctx, "github/app-key", value); err != nil {
		t.Fatal(err)
	}
	got, err := f.s.Get(ctx, "github/app-key")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Reveal(), value) {
		t.Fatalf("got %q", got.Reveal())
	}

	// Survives a restart with the same key.
	if err := f.reopen(t, f.key); err != nil {
		t.Fatal(err)
	}
	got, err = f.s.Get(ctx, "github/app-key")
	if err != nil || !bytes.Equal(got.Reveal(), value) {
		t.Fatalf("after reopen: %q, %v", got.Reveal(), err)
	}
}

func TestNoPlaintextInDatabase(t *testing.T) {
	f := newFixture(t)
	value := []byte("plaintext-marker-7f3a9c")
	if err := f.s.Put(ctx, "marker", value); err != nil {
		t.Fatal(err)
	}
	_ = f.db.Close()
	for _, suffix := range []string{"", "-wal"} {
		b, err := os.ReadFile(filepath.Join(f.dir, store.FileName+suffix))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if bytes.Contains(b, value) {
			t.Errorf("plaintext found in %s%s", store.FileName, suffix)
		}
	}
}

func TestPutReplaces(t *testing.T) {
	f := newFixture(t)
	for _, v := range []string{"one", "two"} {
		if err := f.s.Put(ctx, "x", []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := f.s.Get(ctx, "x")
	if err != nil || string(got.Reveal()) != "two" {
		t.Fatalf("got %q, %v", got.Reveal(), err)
	}
}

func TestWrongMasterKeyRefused(t *testing.T) {
	f := newFixture(t)
	if err := f.s.Put(ctx, "x", []byte("v")); err != nil {
		t.Fatal(err)
	}
	err := f.reopen(t, newKey(t))
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("err = %v, want the wrong key refused", err)
	}
}

func TestCorruptCanaryRefused(t *testing.T) {
	f := newFixture(t)
	f.exec(t, `UPDATE master_keys SET canary = zeroblob(60)`)
	err := f.reopen(t, f.key)
	if err == nil || !strings.Contains(err.Error(), "canary") {
		t.Fatalf("err = %v, want a canary failure", err)
	}
}

func TestTamperedRowsFailToDecrypt(t *testing.T) {
	cols := []string{"ciphertext", "nonce", "wrapped_key"}
	for _, col := range cols {
		t.Run(col, func(t *testing.T) {
			f := newFixture(t)
			if err := f.s.Put(ctx, "x", []byte("value")); err != nil {
				t.Fatal(err)
			}
			f.flipByte(t, col, "x", -1)
			if _, err := f.s.Get(ctx, "x"); err == nil {
				t.Fatalf("tampered %s decrypted", col)
			}
		})
	}
}

func TestMovedCiphertextFailsToDecrypt(t *testing.T) {
	f := newFixture(t)
	if err := f.s.Put(ctx, "attacker-readable", []byte("harmless")); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Put(ctx, "github/app-key", []byte("the real key")); err != nil {
		t.Fatal(err)
	}
	// Copy the valuable row's encrypted fields onto another name.
	f.exec(t, `UPDATE secrets SET (wrapped_key, nonce, ciphertext) =
		(SELECT wrapped_key, nonce, ciphertext FROM secrets WHERE name = 'github/app-key')
		WHERE name = 'attacker-readable'`)
	if s, err := f.s.Get(ctx, "attacker-readable"); err == nil {
		t.Fatalf("moved ciphertext decrypted under another name: %q", s.Reveal())
	}
}

func TestDeleteAndList(t *testing.T) {
	f := newFixture(t)
	for _, n := range []string{"b", "a", "c"} {
		if err := f.s.Put(ctx, n, []byte("v")); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.s.Delete(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Delete(ctx, "b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v, want ErrNotFound", err)
	}
	if _, err := f.s.Get(ctx, "b"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get deleted: %v, want ErrNotFound", err)
	}
	list, err := f.s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, i := range list {
		names = append(names, i.Name)
	}
	if strings.Join(names, ",") != "a,c" {
		t.Errorf("list = %v", names)
	}
}

func TestPutValidation(t *testing.T) {
	f := newFixture(t)
	for _, name := range []string{"", "Upper", "-lead", "has space", "dot/../dot\x00", strings.Repeat("a", 129), "ünï"} {
		if err := f.s.Put(ctx, name, []byte("v")); err == nil {
			t.Errorf("Put(%q) accepted", name)
		}
	}
	if err := f.s.Put(ctx, "ok", nil); err == nil {
		t.Error("empty value accepted")
	}
	if err := f.s.Put(ctx, "ok", make([]byte, MaxSecretSize+1)); err == nil {
		t.Error("oversized value accepted")
	}
	if err := f.s.Put(ctx, "ok", make([]byte, MaxSecretSize)); err != nil {
		t.Errorf("max-size value refused: %v", err)
	}
}

func TestSecretNeverPrints(t *testing.T) {
	const value = "s3cr3t-value-do-not-print"
	s := NewSecret([]byte(value))
	type holder struct {
		Token Secret
		Ptr   *Secret
	}
	h := holder{Token: s, Ptr: &s}

	var outputs []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%c", "%U", "%T %v", "%8.3v"} {
		outputs = append(outputs, fmt.Sprintf(verb, s), fmt.Sprintf(verb, h), fmt.Sprintf(verb, &s))
	}
	outputs = append(outputs, fmt.Sprint(s), fmt.Sprintln(s), s.String())

	j, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(j))
	jm, _ := json.Marshal(map[string]any{"s": s})
	outputs = append(outputs, string(jm))

	for _, format := range []string{"json", "text"} {
		var buf bytes.Buffer
		var handler slog.Handler = slog.NewJSONHandler(&buf, nil)
		if format == "text" {
			handler = slog.NewTextHandler(&buf, nil)
		}
		slog.New(handler).Info("minted", "token", s, "holder", h, "any", any(s))
		outputs = append(outputs, buf.String())
	}

	// Every form the bytes could take: text, hex either case, decimal or
	// octal byte lists, and base64 (JSON's encoding of []byte).
	forms := []string{
		value,
		fmt.Sprintf("%x", value), fmt.Sprintf("%X", value),
		strings.Trim(fmt.Sprintf("%d", []byte(value)), "[]"),
		strings.Trim(fmt.Sprintf("%o", []byte(value)), "[]"),
		base64.StdEncoding.EncodeToString([]byte(value)),
	}
	for _, out := range outputs {
		for _, form := range forms {
			if strings.Contains(out, form) {
				t.Errorf("secret leaked as %q in: %s", form, out)
			}
		}
	}
	if !strings.Contains(fmt.Sprint(s), Redacted) {
		t.Errorf("Sprint = %q, want %q", fmt.Sprint(s), Redacted)
	}
}

func TestErrorsNeverContainValues(t *testing.T) {
	f := newFixture(t)
	if err := f.s.Put(ctx, "x", []byte("value-in-error-check")); err != nil {
		t.Fatal(err)
	}
	f.flipByte(t, "ciphertext", "x", 0)
	_, err := f.s.Get(ctx, "x")
	if err == nil || strings.Contains(err.Error(), "value-in-error-check") {
		t.Fatalf("err = %v", err)
	}
}

func auditActions(t *testing.T, f *fixture) []string {
	t.Helper()
	recs, err := audit.Tail(ctx, f.db.Read(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		out = append(out, r.Action+":"+r.Decision)
	}
	return out
}

func TestSecretChangesAreAuditedByNameOnly(t *testing.T) {
	f := newFixture(t)
	const value = "audit-must-not-see-this-value"
	if err := f.s.Put(ctx, "github/app-key", []byte(value)); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Delete(ctx, "github/app-key"); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(auditActions(t, f), ",")
	want := "master_key.record:allow,secret.put:allow,secret.delete:allow"
	if got != want {
		t.Errorf("audit = %s, want %s", got, want)
	}
	recs, _ := audit.Tail(ctx, f.db.Read(), audit.Filter{Limit: 100})
	for _, r := range recs {
		if strings.Contains(string(r.Params), value) {
			t.Errorf("value in audit params: %s", r.Params)
		}
	}
	if strings.Contains(f.out.String(), value) {
		t.Error("value in the audit stream")
	}
	if !strings.Contains(string(recs[1].Params), "github/app-key") {
		t.Errorf("put not audited by name: %s", recs[1].Params)
	}
}

func TestFailedPutIsNotAudited(t *testing.T) {
	f := newFixture(t)
	before := len(auditActions(t, f))
	if err := f.s.Put(ctx, "Bad Name", []byte("v")); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := f.s.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if after := len(auditActions(t, f)); after != before {
		t.Errorf("audit grew from %d to %d for changes that didn't happen", before, after)
	}
}

func TestKeyChecksAreAudited(t *testing.T) {
	f := newFixture(t)
	if err := f.reopen(t, f.key); err != nil {
		t.Fatal(err)
	}
	if err := f.reopen(t, newKey(t)); err == nil {
		t.Fatal("wrong key accepted")
	}
	got := strings.Join(auditActions(t, f), ",")
	want := "master_key.record:allow,master_key.verify:allow,master_key.verify:deny"
	if got != want {
		t.Errorf("audit = %s, want %s", got, want)
	}
}
