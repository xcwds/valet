package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/connector/fake"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/pipeline"
	"github.com/xcwds/valet/internal/store"
)

// Policy plugs into the pipeline: the rule decides, the audit log names it,
// and a deny never reaches the connector.
func TestPolicyDrivesThePipeline(t *testing.T) {
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f := &fake.Connector{}
	reg, _ := connector.NewRegistry(f)
	pol := mustLoad(t, `
role: bot
rules:
  - name: no-shouting
    action: fake.echo
    when: params.message.upperAscii() == params.message
    decision: deny
    reason: no shouting
  - name: echo
    action: fake.echo
    decision: allow
`)
	logger := logging.New(&bytes.Buffer{}, "json", slog.LevelError)
	pl := pipeline.New(reg, pol, audit.New(db, logger), connector.NewCache(), logger)
	p := jobs.Principal{SessionID: "ses-1", Job: jobs.Job{ID: "job-aaaaaaaa", Role: "bot", ExpiresAt: time.Now().Add(time.Hour)}}

	if _, err := pl.Run(ctx, p, "mcp", "fake.echo", json.RawMessage(`{"message":"hello"}`)); err != nil {
		t.Fatalf("allowed echo: %v", err)
	}
	_, err = pl.Run(ctx, p, "mcp", "fake.echo", json.RawMessage(`{"message":"HELLO"}`))
	var denied *pipeline.Denied
	if !errors.As(err, &denied) || denied.Rule != "bot/no-shouting" || denied.Reason != "no shouting" {
		t.Fatalf("err = %v", err)
	}
	if _, executed, _ := f.Snapshot(); len(executed) != 1 {
		t.Errorf("executed %v, want only the allowed echo", executed)
	}
	recs, _ := audit.Tail(ctx, db.Read(), audit.Filter{Decision: audit.Deny})
	if len(recs) != 1 || recs[0].Rule != "bot/no-shouting" {
		t.Errorf("audit = %+v", recs)
	}
}
