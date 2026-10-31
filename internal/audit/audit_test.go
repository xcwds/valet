package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/store"
)

var ctx = context.Background()

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type fixture struct {
	db  *store.Store
	log *Log
	out *syncBuffer
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	out := &syncBuffer{}
	return &fixture{db: db, log: New(db, logging.New(out, "json", slog.LevelError)), out: out}
}

func event(action string) Event {
	return Event{Interface: InterfaceMCP, Action: action, Decision: Allow, JobID: "job-1", Params: map[string]any{"repo": "xcwds/site"}}
}

func (f *fixture) appendN(t *testing.T, n int) {
	t.Helper()
	for i := range n {
		if _, err := f.log.Append(ctx, event(fmt.Sprintf("github.pr.comment.%d", i))); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *fixture) verify(t *testing.T) VerifyResult {
	t.Helper()
	res, err := Verify(ctx, f.db.Read())
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// tamper runs SQL with the append-only triggers dropped, as an attacker with
// write access to the database file could.
func (f *fixture) tamper(t *testing.T, stmts ...string) {
	t.Helper()
	if err := f.db.Write(ctx, func(tx *sql.Tx) error {
		for _, s := range append([]string{
			`DROP TRIGGER audit_events_no_update`, `DROP TRIGGER audit_events_no_delete`,
		}, stmts...) {
			if _, err := tx.Exec(s); err != nil {
				return fmt.Errorf("%s: %w", s, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestChainVerifies(t *testing.T) {
	f := newFixture(t)
	if res := f.verify(t); !res.OK() || res.Count != 0 {
		t.Fatalf("empty log: %+v", res)
	}
	f.appendN(t, 5)
	res := f.verify(t)
	if !res.OK() || res.Count != 5 || res.LastSeq != 5 {
		t.Fatalf("verify = %+v", res)
	}
}

func TestFirstRecordChainsFromGenesis(t *testing.T) {
	f := newFixture(t)
	rec, err := f.log.Append(ctx, event("valetd.start"))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Seq != 1 || rec.PrevHash == "" || rec.Hash == "" || rec.Hash == rec.PrevHash {
		t.Fatalf("first record = %+v", rec)
	}
	rec2, _ := f.log.Append(ctx, event("valetd.start"))
	if rec2.PrevHash != rec.Hash {
		t.Fatal("second record does not chain to the first")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	tests := map[string]struct {
		stmts      []string
		wantBroken int64
		wantReason string
	}{
		"edited decision": {[]string{`UPDATE audit_events SET decision = 'allow', action = 'x' WHERE seq = 3`}, 3, "edited"},
		"edited params":   {[]string{`UPDATE audit_events SET params = '{"repo":"other/repo"}' WHERE seq = 2`}, 2, "edited"},
		"deleted middle":  {[]string{`DELETE FROM audit_events WHERE seq = 3`}, 4, "deleted or reordered"},
		"deleted first":   {[]string{`DELETE FROM audit_events WHERE seq = 1`}, 2, "deleted or reordered"},
		"renumbered after delete": {[]string{
			`DELETE FROM audit_events WHERE seq = 3`,
			`UPDATE audit_events SET seq = seq - 1 WHERE seq > 3`,
		}, 3, "prev_hash"},
		"relinked after delete": {[]string{
			`DELETE FROM audit_events WHERE seq = 3`,
			`UPDATE audit_events SET prev_hash = (SELECT hash FROM audit_events WHERE seq = 2) WHERE seq = 4`,
			`UPDATE audit_events SET seq = seq - 1 WHERE seq > 3`,
		}, 3, "edited"},
		"reordered": {[]string{
			`UPDATE audit_events SET seq = 100 WHERE seq = 2`,
			`UPDATE audit_events SET seq = 2 WHERE seq = 3`,
			`UPDATE audit_events SET seq = 3 WHERE seq = 100`,
		}, 2, "prev_hash"},
		"forged hash": {[]string{`UPDATE audit_events SET hash = zeroblob(32) WHERE seq = 5`}, 5, "edited"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.appendN(t, 5)
			f.tamper(t, tt.stmts...)
			res := f.verify(t)
			if res.OK() {
				t.Fatalf("tampering went undetected: %+v", res)
			}
			if res.BrokenSeq != tt.wantBroken || !strings.Contains(res.Reason, tt.wantReason) {
				t.Errorf("broken at %d (%s), want %d (%s)", res.BrokenSeq, res.Reason, tt.wantBroken, tt.wantReason)
			}
		})
	}
}

func TestConcurrentAppendsAreGapFree(t *testing.T) {
	f := newFixture(t)
	const workers, each = 16, 20
	var wg sync.WaitGroup
	errc := make(chan error, workers*each)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if _, err := f.log.Append(ctx, event(fmt.Sprintf("a.%d.%d", w, i))); err != nil {
					errc <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		t.Fatal(err)
	}
	res := f.verify(t)
	if !res.OK() || res.Count != workers*each || res.LastSeq != workers*each {
		t.Fatalf("verify = %+v", res)
	}
}

func TestAppendTxRollsBackWithItsChange(t *testing.T) {
	f := newFixture(t)
	f.appendN(t, 1)
	err := f.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := f.log.AppendTx(ctx, tx, event("secret.put")); err != nil {
			return err
		}
		return fmt.Errorf("the change failed")
	})
	if err == nil {
		t.Fatal("want the error")
	}
	f.appendN(t, 1)
	res := f.verify(t)
	if !res.OK() || res.Count != 2 {
		t.Fatalf("verify = %+v; the rolled-back event left a trace", res)
	}
}

func TestInvalidEventsAreRefused(t *testing.T) {
	f := newFixture(t)
	bad := []Event{
		{Interface: "smoke-signals", Action: "a", Decision: Allow},
		{Interface: InterfaceMCP, Action: "a", Decision: "maybe"},
		{Interface: InterfaceMCP, Action: "", Decision: Allow},
		{Interface: InterfaceMCP, Action: "Has Spaces", Decision: Allow},
		{Interface: InterfaceMCP, Action: "a", Decision: Allow, Params: func() {}},
	}
	for _, ev := range bad {
		if _, err := f.log.Append(ctx, ev); err == nil {
			t.Errorf("accepted %+v", ev)
		}
	}
	if res := f.verify(t); res.Count != 0 {
		t.Fatalf("refused events were stored: %+v", res)
	}
}

func TestAppendFailsWhenTheDatabaseDoes(t *testing.T) {
	f := newFixture(t)
	_ = f.db.Close()
	if _, err := f.log.Append(ctx, event("github.pr.merge")); err == nil {
		t.Fatal("Append succeeded with the database closed; the caller would act without a record")
	}
	if strings.Contains(f.out.String(), "github.pr.merge") {
		t.Error("an unrecorded event was emitted on stdout")
	}
}

// secretish mimics secrets.Secret without importing it.
type secretish struct{}

func (secretish) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

func TestParamsRedactionAndTruncation(t *testing.T) {
	f := newFixture(t)
	long := strings.Repeat("x", MaxStringLen+1)
	rec, err := f.log.Append(ctx, Event{
		Interface: InterfaceMCP, Action: "github.pr.comment", Decision: Allow,
		Params: map[string]any{
			"repo":   "xcwds/site",
			"body":   long,
			"short":  strings.Repeat("y", MaxStringLen),
			"marked": "value-marked-sensitive",
			"nested": map[string]any{"Authorization": "Bearer ghs_abc", "list": []any{map[string]any{"api_key": "k-123"}}},
			"Token":  "tok-456",
			"held":   secretish{},
		},
		Sensitive: []string{"marked"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := string(rec.Params)
	for _, leaked := range []string{"value-marked-sensitive", "ghs_abc", "k-123", "tok-456", long} {
		if strings.Contains(p, leaked) {
			t.Errorf("params kept %q: %s", leaked[:min(len(leaked), 30)], p)
		}
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Params, &got); err != nil {
		t.Fatal(err)
	}
	body, _ := got["body"].(map[string]any)
	if body["truncated"] != true || body["length"] != float64(MaxStringLen+1) || len(body["sha256"].(string)) != 64 {
		t.Errorf("body = %v, want length and sha256", got["body"])
	}
	if got["short"] != strings.Repeat("y", MaxStringLen) {
		t.Error("a string at the limit was truncated")
	}
	if got["repo"] != "xcwds/site" {
		t.Error("an ordinary field was changed")
	}
}

func TestParamsCanonical(t *testing.T) {
	a, err := canonicalParams(map[string]any{"b": 1, "a": []int{2, 3}, "c": map[string]any{"z": 1, "y": 2.5}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonicalParams(struct {
		C map[string]any `json:"c"`
		A []int          `json:"a"`
		B int            `json:"b"`
	}{map[string]any{"y": 2.5, "z": 1}, []int{2, 3}, 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) || string(a) != `{"a":[2,3],"b":1,"c":{"y":2.5,"z":1}}` {
		t.Fatalf("not canonical: %s vs %s", a, b)
	}
	big, _ := canonicalParams(map[string]any{"n": int64(9007199254740993)}, nil)
	if string(big) != `{"n":9007199254740993}` {
		t.Errorf("large integer changed: %s", big)
	}
}

func TestEmitIsAlwaysWritten(t *testing.T) {
	f := newFixture(t) // logger at error level
	rec, err := f.log.Append(ctx, event("github.pr.review.submit"))
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(f.out.String())
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("not one JSON line: %q", line)
	}
	if got["level"] != "AUDIT" || got["component"] != "clio" || got["action"] != "github.pr.review.submit" ||
		got["hash"] != rec.Hash || got["seq"] != float64(1) {
		t.Errorf("line = %v", got)
	}
	if params, ok := got["params"].(map[string]any); !ok || params["repo"] != "xcwds/site" {
		t.Errorf("params not embedded as JSON: %v", got["params"])
	}
}

func TestTail(t *testing.T) {
	f := newFixture(t)
	for i := range 6 {
		ev := event(fmt.Sprintf("a.%d", i))
		if i%2 == 1 {
			ev.Decision = Deny
			ev.JobID = "job-2"
		}
		if _, err := f.log.Append(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	recs, err := Tail(ctx, f.db.Read(), Filter{Limit: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 4 || recs[0].Seq != 3 || recs[3].Seq != 6 {
		t.Fatalf("tail 4 = %v, want seq 3..6 oldest first", seqs(recs))
	}
	recs, _ = Tail(ctx, f.db.Read(), Filter{Decision: Deny})
	if got := seqs(recs); fmt.Sprint(got) != "[2 4 6]" {
		t.Errorf("denies = %v", got)
	}
	recs, _ = Tail(ctx, f.db.Read(), Filter{JobID: "job-1", Limit: 2})
	if got := seqs(recs); fmt.Sprint(got) != "[3 5]" {
		t.Errorf("job-1 last 2 = %v", got)
	}
}

func seqs(rs []Record) []int64 {
	var out []int64
	for _, r := range rs {
		out = append(out, r.Seq)
	}
	return out
}
