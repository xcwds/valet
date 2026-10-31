package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/connector/fake"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/store"
)

var ctx = context.Background()

// policyFunc adapts a function to Policy.
type policyFunc func(Request) (Decision, error)

func (f policyFunc) Decide(_ context.Context, r Request) (Decision, error) { return f(r) }

// allowEcho allows fake.echo and denies everything else, like a real role.
var allowEcho = policyFunc(func(r Request) (Decision, error) {
	if r.Action == "fake.echo" {
		return Decision{Effect: Allow, Rule: "echo-ok"}, nil
	}
	return Decision{Effect: Deny, Rule: "no-danger", Reason: "not for this role"}, nil
})

type fixture struct {
	db   *store.Store
	fake *fake.Connector
	pl   *Pipeline
	p    jobs.Principal
}

func newFixture(t *testing.T, policy Policy) *fixture {
	t.Helper()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := &fake.Connector{}
	reg, err := connector.NewRegistry(f)
	if err != nil {
		t.Fatal(err)
	}
	logger := logging.New(&bytes.Buffer{}, "json", slog.LevelInfo)
	pl := New(reg, policy, audit.New(db, logger), connector.NewCache(), logger)
	p := jobs.Principal{SessionID: "ses-1", Job: jobs.Job{ID: "job-aaaaaaaa", Role: "reviewer", ExpiresAt: time.Now().Add(time.Hour)}}
	return &fixture{db: db, fake: f, pl: pl, p: p}
}

func (f *fixture) trail(t *testing.T) []audit.Record {
	t.Helper()
	recs, err := audit.Tail(ctx, f.db.Read(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func (f *fixture) run(action, params string) (connector.Result, error) {
	return f.pl.Run(ctx, f.p, audit.InterfaceMCP, action, json.RawMessage(params))
}

func TestAllowExecutes(t *testing.T) {
	f := newFixture(t, allowEcho)
	res, err := f.run("fake.echo", `{"message":"hi","note":"keep-out-of-audit"}`)
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := res.Body.(map[string]any); body["echo"] != "hi" || res.UpstreamStatus != 200 {
		t.Fatalf("result = %+v", res)
	}
	mints, executed, _ := f.fake.Snapshot()
	if len(mints) != 1 || len(executed) != 1 {
		t.Fatalf("mints %v, executed %v", mints, executed)
	}

	recs := f.trail(t)
	if len(recs) != 2 {
		t.Fatalf("%d audit records, want decision and result", len(recs))
	}
	d, r := recs[0], recs[1]
	if d.Decision != audit.Allow || d.Rule != "echo-ok" || d.Action != "fake.echo" || d.JobID != "job-aaaaaaaa" || d.Interface != "mcp" {
		t.Errorf("decision = %+v", d)
	}
	if strings.Contains(string(d.Params), "keep-out-of-audit") {
		t.Errorf("a param the spec marks sensitive was recorded: %s", d.Params)
	}
	if r.Decision != audit.Info || r.UpstreamStatus != 200 || !strings.Contains(string(r.Params), `"result_of":1`) {
		t.Errorf("result = %+v", r)
	}
}

func TestRefusalsNeverMint(t *testing.T) {
	cases := []struct {
		name, action, params string
		policy               Policy
		wantRule, wantReason string
	}{
		{"policy deny", "fake.danger", `{"target":"x"}`, allowEcho, "no-danger", "not for this role"},
		{"default deny", "fake.echo", `{"message":"hi"}`, DenyAll{}, "default", "no policy"},
		{"unknown action", "fake.nope", `{}`, allowEcho, "", "unknown action"},
		{"unknown connector", "github.pr.merge", `{}`, allowEcho, "", "unknown action"},
		{"invalid params", "fake.echo", `{"message":"hi","extra":true}`, allowEcho, "", "invalid params"},
		{"not JSON", "fake.echo", `{`, allowEcho, "", "invalid params"},
		{"needs approval", "fake.echo", `{"message":"hi"}`, policyFunc(func(Request) (Decision, error) {
			return Decision{Effect: RequireApproval, Rule: "merge-needs-a-human"}, nil
		}), "merge-needs-a-human", "approvals are not available"},
		{"policy error", "fake.echo", `{"message":"hi"}`, policyFunc(func(Request) (Decision, error) {
			return Decision{}, errors.New("cel: no such key")
		}), "policy-error", "policy evaluation failed"},
		{"unknown effect", "fake.echo", `{"message":"hi"}`, policyFunc(func(Request) (Decision, error) {
			return Decision{Effect: "maybe", Rule: "r"}, nil
		}), "r", "unknown policy effect"},
		{"hostile action name", "FAKE.ECHO; drop", `{}`, allowEcho, "", "unknown action"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.policy)
			_, err := f.run(c.action, c.params)
			var denied *Denied
			if !errors.As(err, &denied) {
				t.Fatalf("err = %v, want *Denied", err)
			}
			if denied.Rule != c.wantRule || !strings.Contains(denied.Reason, c.wantReason) {
				t.Errorf("denied = %+v", denied)
			}
			if mints, executed, _ := f.fake.Snapshot(); len(mints)+len(executed) != 0 {
				t.Fatalf("refused request reached the connector: mints %v, executed %v", mints, executed)
			}
			recs := f.trail(t)
			if len(recs) != 1 || recs[0].Decision != audit.Deny || recs[0].Rule != c.wantRule || !strings.Contains(recs[0].Error, c.wantReason) {
				t.Errorf("audit = %+v", recs)
			}
		})
	}
}

func TestValidationErrorsKeepValuesOutOfTheAudit(t *testing.T) {
	f := newFixture(t, allowEcho)
	secret := "sk-" + strings.Repeat("q", 120) // too long for message's maxLength
	_, err := f.run("fake.echo", `{"message":"`+secret+`","note":"also-secret"}`)
	var denied *Denied
	if !errors.As(err, &denied) || !strings.Contains(denied.Reason, "maxLength") {
		t.Fatalf("err = %v; the agent should get the detail", err)
	}
	recs := f.trail(t)
	if len(recs) != 1 {
		t.Fatalf("audit = %+v", recs)
	}
	r := recs[0]
	if r.Error != "invalid params" {
		t.Errorf("audit error = %q, want the generic reason", r.Error)
	}
	if strings.Contains(r.Error+string(r.Params), "also-secret") {
		t.Errorf("a sensitive param reached the audit record: %s / %s", r.Error, r.Params)
	}
	if strings.Contains(r.Error, secret) {
		t.Error("the offending value reached the audit error")
	}
}

func TestPolicySeesValidatedParams(t *testing.T) {
	var seen Request
	f := newFixture(t, policyFunc(func(r Request) (Decision, error) {
		seen = r
		return Decision{Effect: Deny, Rule: "look"}, nil
	}))
	_, _ = f.run("fake.echo", `{"message":"hi"}`)
	if seen.Job.ID != "job-aaaaaaaa" || seen.Action != "fake.echo" || seen.Params["message"] != "hi" || seen.Spec.Risk != connector.RiskLow || seen.Interface != "mcp" {
		t.Errorf("policy saw %+v", seen)
	}
}

func TestAuditFailureStopsTheAction(t *testing.T) {
	f := newFixture(t, allowEcho)
	_ = f.db.Close()
	if _, err := f.run("fake.echo", `{"message":"hi"}`); err == nil {
		t.Fatal("ran without a record")
	}
	if mints, executed, _ := f.fake.Snapshot(); len(mints)+len(executed) != 0 {
		t.Fatalf("unrecorded request reached the connector: %v %v", mints, executed)
	}
}

func TestUpstreamFailuresAreRecorded(t *testing.T) {
	t.Run("mint", func(t *testing.T) {
		f := newFixture(t, allowEcho)
		f.fake.MintErr = errors.New("installation not found")
		if _, err := f.run("fake.echo", `{"message":"hi"}`); err == nil {
			t.Fatal("want the mint error")
		}
		recs := f.trail(t)
		if len(recs) != 2 || !strings.Contains(recs[1].Error, "installation not found") {
			t.Errorf("audit = %+v", recs)
		}
		if _, executed, _ := f.fake.Snapshot(); len(executed) != 0 {
			t.Error("executed without a credential")
		}
	})
	t.Run("execute", func(t *testing.T) {
		f := newFixture(t, allowEcho)
		f.fake.ExecErr = errors.New("upstream 502")
		if _, err := f.run("fake.echo", `{"message":"hi"}`); err == nil {
			t.Fatal("want the execute error")
		}
		recs := f.trail(t)
		if len(recs) != 2 || recs[1].UpstreamStatus != 502 || !strings.Contains(recs[1].Error, "upstream 502") {
			t.Errorf("audit = %+v", recs)
		}
	})
}

func TestCredentialReusedAcrossRequests(t *testing.T) {
	f := newFixture(t, allowEcho)
	for range 3 {
		if _, err := f.run("fake.echo", `{"message":"hi"}`); err != nil {
			t.Fatal(err)
		}
	}
	if mints, executed, _ := f.fake.Snapshot(); len(mints) != 1 || len(executed) != 3 {
		t.Errorf("mints %d, executed %d", len(mints), len(executed))
	}
}
