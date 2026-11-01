// Package audit is Clio, Valet's audit log (RFC decision 6).
//
// Every decision is recorded, allowed or not, in an append-only table whose
// rows form a hash chain: each row's hash covers its own fields and the
// previous row's hash, so editing, deleting or reordering a row breaks the
// chain from that point on (Verify finds it). Each event is also written to
// stdout as a JSON line, at a level no log setting hides, for shipping off the
// host.
//
// If an event can't be recorded, the request it describes must fail: callers
// treat an Append error as a deny. Valet never acts without a record.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/store"
)

// Interfaces an event can come through.
const (
	InterfaceMCP    = "mcp"
	InterfaceGit    = "git"
	InterfaceEgress = "egress"
	InterfaceAdmin  = "admin"
	InterfaceCLI    = "cli"
	InterfaceEnroll = "enroll" // a container exchanging its enrollment code (#19)
	InterfaceSystem = "system" // valetd itself: start-up, key checks
)

// Decisions.
const (
	Allow           = "allow"
	Deny            = "deny"
	RequireApproval = "require_approval"
	Approved        = "approved"
	Rejected        = "rejected"
	Info            = "info" // a record of something that wasn't a decision
)

var (
	interfaces = map[string]bool{InterfaceMCP: true, InterfaceGit: true, InterfaceEgress: true, InterfaceAdmin: true, InterfaceCLI: true, InterfaceEnroll: true, InterfaceSystem: true}
	decisions  = map[string]bool{Allow: true, Deny: true, RequireApproval: true, Approved: true, Rejected: true, Info: true}
	actionName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

// genesis is the previous hash of the first event.
var genesis = func() []byte { s := sha256.Sum256([]byte("valet audit genesis v1")); return s[:] }()

// Event is what a caller records.
type Event struct {
	JobID          string
	SessionID      string
	Interface      string
	Action         string
	Params         any      // anything JSON-encodable; canonicalized and redacted
	Sensitive      []string // top-level params keys to redact, from the ActionSpec
	Decision       string
	Rule           string
	UpstreamStatus int // 0 when there was no upstream call
	Error          string
}

// Record is a stored event. Its JSON form is what is hashed (without Hash)
// and what is emitted on stdout.
type Record struct {
	Seq            int64           `json:"seq"`
	Time           string          `json:"time"`
	JobID          string          `json:"job_id,omitempty"`
	SessionID      string          `json:"session_id,omitempty"`
	Interface      string          `json:"interface"`
	Action         string          `json:"action"`
	Params         json.RawMessage `json:"params"`
	Decision       string          `json:"decision"`
	Rule           string          `json:"rule,omitempty"`
	UpstreamStatus int             `json:"upstream_status,omitempty"`
	Error          string          `json:"error,omitempty"`
	PrevHash       string          `json:"prev_hash"`
	Hash           string          `json:"hash,omitempty"`
}

// computeHash is SHA-256 over the record's canonical JSON with Hash empty.
// PrevHash is one of the fields, which is what chains the rows.
func computeHash(r Record) (string, error) {
	r.Hash = ""
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Log appends events.
type Log struct {
	db  *store.Store
	out *slog.Logger
	now func() time.Time
}

// New returns a Log writing to db and emitting each record on out.
func New(db *store.Store, out *slog.Logger) *Log {
	return &Log{db: db, out: logging.For(out, logging.Clio), now: time.Now}
}

// Append records ev in its own transaction and emits it. An error means the
// event was not recorded: the caller must deny what it describes.
func (l *Log) Append(ctx context.Context, ev Event) (Record, error) {
	var rec Record
	err := l.db.Write(ctx, func(tx *sql.Tx) error {
		var err error
		rec, err = l.AppendTx(ctx, tx, ev)
		return err
	})
	if err != nil {
		return Record{}, err
	}
	l.Emit(ctx, rec)
	return rec, nil
}

// AppendTx records ev inside tx, so it commits or rolls back with the change
// it describes. The caller must Emit the record after a successful commit.
func (l *Log) AppendTx(ctx context.Context, tx *sql.Tx, ev Event) (Record, error) {
	if !interfaces[ev.Interface] {
		return Record{}, fmt.Errorf("audit: unknown interface %q", ev.Interface)
	}
	if !decisions[ev.Decision] {
		return Record{}, fmt.Errorf("audit: unknown decision %q", ev.Decision)
	}
	if !actionName.MatchString(ev.Action) {
		return Record{}, fmt.Errorf("audit: invalid action %q", ev.Action)
	}
	params, err := canonicalParams(ev.Params, ev.Sensitive)
	if err != nil {
		return Record{}, err
	}

	// The single writer connection and BEGIN IMMEDIATE make this read and
	// the insert below atomic: sequence numbers have no gaps or duplicates.
	var lastSeq int64
	prev := genesis
	err = tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Record{}, fmt.Errorf("audit: %w", err)
	}

	rec := Record{
		Seq:            lastSeq + 1,
		Time:           l.now().UTC().Format(time.RFC3339Nano),
		JobID:          ev.JobID,
		SessionID:      ev.SessionID,
		Interface:      ev.Interface,
		Action:         ev.Action,
		Params:         params,
		Decision:       ev.Decision,
		Rule:           ev.Rule,
		UpstreamStatus: ev.UpstreamStatus,
		Error:          ev.Error,
		PrevHash:       hex.EncodeToString(prev),
	}
	if rec.Hash, err = computeHash(rec); err != nil {
		return Record{}, fmt.Errorf("audit: %w", err)
	}
	hash, _ := hex.DecodeString(rec.Hash)

	_, err = tx.ExecContext(ctx, `
		INSERT INTO audit_events (seq, time, job_id, session_id, interface, action, params,
			decision, rule, upstream_status, error, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Seq, rec.Time, nullable(rec.JobID), nullable(rec.SessionID), rec.Interface, rec.Action,
		string(rec.Params), rec.Decision, nullable(rec.Rule), nullableInt(rec.UpstreamStatus),
		nullable(rec.Error), prev, hash)
	if err != nil {
		return Record{}, fmt.Errorf("audit: %w", err)
	}
	return rec, nil
}

// Emit writes rec to the log stream as one JSON line at LevelAudit.
func (l *Log) Emit(ctx context.Context, rec Record) {
	l.out.LogAttrs(ctx, logging.LevelAudit, "audit",
		slog.Int64("seq", rec.Seq),
		slog.String("event_time", rec.Time),
		slog.String("job_id", rec.JobID),
		slog.String("session_id", rec.SessionID),
		slog.String("interface", rec.Interface),
		slog.String("action", rec.Action),
		slog.Any("params", rec.Params),
		slog.String("decision", rec.Decision),
		slog.String("rule", rec.Rule),
		slog.Int("upstream_status", rec.UpstreamStatus),
		slog.String("error", rec.Error),
		slog.String("hash", rec.Hash),
	)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableInt(n int) any {
	if n == 0 {
		return nil
	}
	return n
}
