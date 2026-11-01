package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/connector/fake"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/pipeline"
	"github.com/xcwds/valet/internal/policy"
	"github.com/xcwds/valet/internal/store"
)

var ctx = context.Background()

const roles = `
role: echoer
rules:
  - name: no-shouting
    action: fake.echo
    when: params.message.upperAscii() == params.message
    decision: deny
    reason: no shouting
  - action: fake.echo
    decision: allow
  - action: gitonly.push
    decision: allow
---
role: nobody
rules:
  - action: fake.danger
    decision: deny
`

type fixture struct {
	srv   *httptest.Server
	db    *store.Store
	jobs  *jobs.Service
	fake  *fake.Connector
	logs  *bytes.Buffer
	token string
	job   jobs.Job
}

func newFixture(t *testing.T, role string) *fixture {
	t.Helper()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logs := &bytes.Buffer{}
	log := logging.New(logs, "json", slog.LevelInfo)
	alog := audit.New(db, log)
	f := &fake.Connector{}
	reg, err := connector.NewRegistry(f, gitOnly{})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load("test", map[string][]byte{"r.yaml": []byte(roles)})
	if err != nil {
		t.Fatal(err)
	}
	js := jobs.NewService(db, alog)
	j, tok, err := js.Create(ctx, jobs.CreateRequest{Role: role, CreatedBy: "admin:test", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	pl := pipeline.New(reg, pol, alog, connector.NewCache(), log)
	iris, err := New(reg, pl, pol, log)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", iris.Handler())
	srv := httptest.NewServer(js.RequireSession(mux))
	t.Cleanup(srv.Close)
	return &fixture{srv: srv, db: db, jobs: js, fake: f, logs: logs, token: tok, job: j}
}

type bearer struct {
	token string
	next  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}

func (f *fixture) connect(t *testing.T, token string) (*sdk.ClientSession, error) {
	t.Helper()
	c := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, nil)
	return c.Connect(ctx, &sdk.StreamableClientTransport{
		Endpoint:             f.srv.URL + "/mcp",
		HTTPClient:           &http.Client{Transport: bearer{token, http.DefaultTransport}},
		MaxRetries:           -1,
		DisableStandaloneSSE: true,
	}, nil)
}

func (f *fixture) session(t *testing.T) *sdk.ClientSession {
	t.Helper()
	cs, err := f.connect(t, f.token)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func text(r *sdk.CallToolResult) string {
	var b strings.Builder
	for _, c := range r.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

func (f *fixture) trail(t *testing.T) []audit.Record {
	t.Helper()
	recs, err := audit.Tail(ctx, f.db.Read(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestListToolsOffersWhatTheRoleCouldUse(t *testing.T) {
	f := newFixture(t, "echoer")
	res, err := f.session(t).ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
		if tool.Name == "fake_echo" {
			b, _ := json.Marshal(tool.InputSchema)
			if !strings.Contains(string(b), `"message"`) || !strings.Contains(string(b), `"additionalProperties":false`) {
				t.Errorf("schema = %s", b)
			}
		}
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "fake_echo" {
		t.Errorf("tools = %v, want only fake_echo", names)
	}
}

func TestCallAllowed(t *testing.T) {
	f := newFixture(t, "echoer")
	res, err := f.session(t).CallTool(ctx, &sdk.CallToolParams{Name: "fake_echo", Arguments: map[string]any{"message": "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError || !strings.Contains(text(res), `"echo":"hi"`) {
		t.Fatalf("result = %+v %q", res, text(res))
	}
	if _, executed, _ := f.fake.Snapshot(); len(executed) != 1 {
		t.Errorf("executed = %v", executed)
	}
	recs := f.trail(t)
	last := recs[len(recs)-2] // decision, then result
	if last.Action != "fake.echo" || last.Decision != "allow" || last.Interface != "mcp" || last.JobID != f.job.ID {
		t.Errorf("audit = %+v", last)
	}
}

func TestCallDenied(t *testing.T) {
	f := newFixture(t, "echoer")
	res, err := f.session(t).CallTool(ctx, &sdk.CallToolParams{Name: "fake_echo", Arguments: map[string]any{"message": "HI"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(text(res), "echoer/no-shouting") || !strings.Contains(text(res), "no shouting") {
		t.Fatalf("result = %q", text(res))
	}
	if _, executed, _ := f.fake.Snapshot(); len(executed) != 0 {
		t.Error("a denied call executed")
	}
}

func TestUnofferedAndUnknownToolsAreDeniedAndAudited(t *testing.T) {
	f := newFixture(t, "echoer")
	cs := f.session(t)
	for _, name := range []string{"fake_danger", "github_pr_merge", "not_a_tool"} {
		res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: map[string]any{"target": "x"}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !res.IsError || !strings.Contains(text(res), "denied") {
			t.Errorf("%s: %q", name, text(res))
		}
	}
	denies := 0
	for _, r := range f.trail(t) {
		if r.Decision == "deny" {
			denies++
		}
	}
	if denies != 3 {
		t.Errorf("%d audited denies, want 3", denies)
	}
	if _, executed, _ := f.fake.Snapshot(); len(executed) != 0 {
		t.Error("an unoffered tool executed")
	}
}

func TestInvalidArgumentsAreDenied(t *testing.T) {
	f := newFixture(t, "echoer")
	res, err := f.session(t).CallTool(ctx, &sdk.CallToolParams{Name: "fake_echo", Arguments: map[string]any{"message": "hi", "extra": 1}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(text(res), "invalid params") {
		t.Fatalf("result = %q", text(res))
	}
}

func TestUpstreamFailureIsGeneric(t *testing.T) {
	f := newFixture(t, "echoer")
	f.fake.ExecErr = errors.New("upstream said: internal detail with ghs_secret")
	res, err := f.session(t).CallTool(ctx, &sdk.CallToolParams{Name: "fake_echo", Arguments: map[string]any{"message": "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(text(res), "HTTP 502") || strings.Contains(text(res), "ghs_secret") || strings.Contains(text(res), "internal detail") {
		t.Fatalf("result = %q", text(res))
	}
}

func TestAuthentication(t *testing.T) {
	f := newFixture(t, "echoer")
	if _, err := f.connect(t, ""); err == nil {
		t.Error("connected without a token")
	}
	if _, err := f.connect(t, "vlt_sess_"+strings.Repeat("a", 52)); err == nil {
		t.Error("connected with an unknown token")
	}
	cs := f.session(t)
	if err := f.jobs.Revoke(ctx, f.job.ID, "admin:test", "test"); err != nil {
		t.Fatal(err)
	}
	// The open session is no use once the job is revoked: every request
	// is authenticated again.
	if _, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake_echo", Arguments: map[string]any{"message": "hi"}}); err == nil {
		t.Error("a revoked job's session still called a tool")
	}
	if _, executed, _ := f.fake.Snapshot(); len(executed) != 0 {
		t.Error("executed after revocation")
	}
}

// Each request acts as the token on that request, never as the session it
// claims to continue.
func TestCallsActAsTheirOwnToken(t *testing.T) {
	f := newFixture(t, "echoer")
	other, otherTok, err := f.jobs.Create(ctx, jobs.CreateRequest{Role: "nobody", CreatedBy: "admin:test", TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := f.connect(t, otherTok)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake_echo", Arguments: map[string]any{"message": "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("the nobody role echoed")
	}
	recs := f.trail(t)
	if last := recs[len(recs)-1]; last.JobID != other.ID {
		t.Errorf("audited as %s, want %s", last.JobID, other.ID)
	}
}

func TestToolNameCollision(t *testing.T) {
	reg, err := connector.NewRegistry(&collider{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(reg, nil, nil, logging.New(&bytes.Buffer{}, "json", slog.LevelInfo)); err == nil || !strings.Contains(err.Error(), "both be tool") {
		t.Fatalf("err = %v", err)
	}
}

type collider struct{ fake.Connector }

func (*collider) Name() string { return "c" }
func (*collider) Actions() []connector.ActionSpec {
	obj := func() *jsonschema.Schema { return connector.Object(map[string]*jsonschema.Schema{}) }
	return []connector.ActionSpec{
		{Name: "a.b_c", Description: "d", Risk: connector.RiskLow, Params: obj()},
		{Name: "a.b.c", Description: "d", Risk: connector.RiskLow, Params: obj()},
	}
}

// gitOnly has an action only the git interface may request, like git.push.
type gitOnly struct{}

func (gitOnly) Name() string { return "gitonly" }
func (gitOnly) Actions() []connector.ActionSpec {
	return []connector.ActionSpec{{
		Name: "push", Description: "Push.", Risk: connector.RiskHigh, Interfaces: []string{"git"},
		Params: connector.Object(map[string]*jsonschema.Schema{"repo": {Type: "string"}}),
	}}
}

func (gitOnly) Mint(context.Context, jobs.Job) (connector.Credential, error) {
	return connector.Credential{}, errors.New("must not mint")
}

func (gitOnly) Execute(context.Context, connector.Credential, jobs.Job, connector.Action) (connector.Result, error) {
	return connector.Result{}, errors.New("must not execute")
}

// An action for another interface is neither offered nor callable over
// MCP, even when the role's policy would allow it.
func TestOtherInterfacesActionsAreNotMCPTools(t *testing.T) {
	f := newFixture(t, "echoer")
	cs := f.session(t)
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		if tool.Name == "gitonly_push" {
			t.Fatal("gitonly_push offered over MCP")
		}
	}
	call, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "gitonly_push", Arguments: map[string]any{"repo": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if !call.IsError || !strings.Contains(text(call), "unknown action") {
		t.Errorf("call = %q", text(call))
	}
	trail := f.trail(t)
	if last := trail[len(trail)-1]; last.Action != "gitonly.push" || last.Decision != "deny" {
		t.Errorf("audit = %+v", last)
	}
}
