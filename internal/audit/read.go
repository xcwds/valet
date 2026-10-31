package audit

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

const selectRecords = `SELECT seq, time, coalesce(job_id, ''), coalesce(session_id, ''), interface,
	action, params, decision, coalesce(rule, ''), coalesce(upstream_status, 0), coalesce(error, ''),
	prev_hash, hash FROM audit_events`

func scanRecord(rows *sql.Rows) (Record, []byte, []byte, error) {
	var r Record
	var params string
	var prev, hash []byte
	err := rows.Scan(&r.Seq, &r.Time, &r.JobID, &r.SessionID, &r.Interface, &r.Action, &params,
		&r.Decision, &r.Rule, &r.UpstreamStatus, &r.Error, &prev, &hash)
	if err != nil {
		return Record{}, nil, nil, err
	}
	r.Params = []byte(params)
	r.PrevHash = hex.EncodeToString(prev)
	r.Hash = hex.EncodeToString(hash)
	return r, prev, hash, nil
}

// Filter selects events for Tail.
type Filter struct {
	JobID    string
	Decision string
	Limit    int // most recent N; 0 means 20
}

// Tail returns the most recent events matching f, oldest first.
func Tail(ctx context.Context, db *sql.DB, f Filter) ([]Record, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}
	var where []string
	var args []any
	if f.JobID != "" {
		where = append(where, "job_id = ?")
		args = append(args, f.JobID)
	}
	if f.Decision != "" {
		where = append(where, "decision = ?")
		args = append(args, f.Decision)
	}
	q := selectRecords
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY seq DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Record
	for rows.Next() {
		r, _, _, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// VerifyResult is the outcome of walking the chain.
type VerifyResult struct {
	Count     int64  // rows checked
	LastSeq   int64  // highest seq seen
	BrokenSeq int64  // first row where the chain breaks; 0 if intact
	Reason    string // why it broke
}

// OK reports whether the chain is intact.
func (v VerifyResult) OK() bool { return v.BrokenSeq == 0 }

// Verify walks every event in order and reports the first break: a gap or
// reordering in seq, a prev_hash that isn't the previous row's hash, or a hash
// that doesn't match the row's contents.
//
// A chain alone can't show that the newest rows were cut off; the stdout copy
// shipped off the host is the check for that.
func Verify(ctx context.Context, db *sql.DB) (VerifyResult, error) {
	rows, err := db.QueryContext(ctx, selectRecords+" ORDER BY seq")
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var res VerifyResult
	prev := hex.EncodeToString(genesis)
	for rows.Next() {
		r, _, _, err := scanRecord(rows)
		if err != nil {
			return res, fmt.Errorf("audit: %w", err)
		}
		res.Count++
		res.LastSeq = r.Seq
		broken := func(why string) (VerifyResult, error) {
			res.BrokenSeq, res.Reason = r.Seq, why
			return res, nil
		}
		if r.Seq != res.Count {
			return broken(fmt.Sprintf("expected seq %d, found %d (a row was deleted or reordered)", res.Count, r.Seq))
		}
		if r.PrevHash != prev {
			return broken("prev_hash is not the previous row's hash (a row was deleted, inserted or reordered)")
		}
		want, err := computeHash(r)
		if err != nil {
			return res, fmt.Errorf("audit: %w", err)
		}
		if r.Hash != want {
			return broken("hash does not match the row's contents (the row was edited)")
		}
		prev = r.Hash
	}
	return res, rows.Err()
}
