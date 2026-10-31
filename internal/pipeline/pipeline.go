// Package pipeline is the one path every agent request takes (RFC
// Architecture): MCP, git and egress all turn traffic into actions and hand
// them here, so they can't drift apart.
//
//	resolve and validate → policy → audit the decision → [approval] →
//	mint (cached per job) → execute → audit the result
//
// Anything but an allow stops before a credential is minted. An audit error
// stops it too: nothing is done that wasn't recorded first.
package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
)

// Effects a policy decision can have.
const (
	Allow           = "allow"
	Deny            = "deny"
	RequireApproval = "require_approval"
)

// Request is what policy decides on.
type Request struct {
	Job       jobs.Job
	Interface string
	Action    string // full name, e.g. github.pr.comment
	Spec      connector.ActionSpec
	Params    map[string]any // validated against the spec; numbers are json.Number
}

// Decision is a policy's answer.
type Decision struct {
	Effect string // Allow, Deny or RequireApproval
	Rule   string // which rule decided, for the audit log and the agent
	Reason string
	Alert  bool // ask for an alert (#15)
	// Detail explains an evaluation error for an operator debugging a rule
	// (valet policy check). It can quote params, so the pipeline neither
	// returns nor audits it.
	Detail string
}

// Policy decides on requests (Themis, #11).
type Policy interface {
	Decide(ctx context.Context, req Request) (Decision, error)
}

// DenyAll is the policy until one is configured: deny by default (RFC
// decision 5).
type DenyAll struct{}

// Decide implements Policy.
func (DenyAll) Decide(context.Context, Request) (Decision, error) {
	return Decision{Effect: Deny, Rule: "default", Reason: "no policy is configured"}, nil
}

// Denied is returned when a request was refused. Its message is safe to show
// the agent.
type Denied struct {
	Rule   string
	Reason string
}

func (d *Denied) Error() string {
	if d.Rule == "" {
		return "denied: " + d.Reason
	}
	return fmt.Sprintf("denied by rule %s: %s", d.Rule, d.Reason)
}

// Pipeline runs requests.
type Pipeline struct {
	reg    *connector.Registry
	policy Policy
	audit  *audit.Log
	cache  *connector.Cache
	log    *slog.Logger
}

// New returns a Pipeline.
func New(reg *connector.Registry, policy Policy, log *audit.Log, cache *connector.Cache, logger *slog.Logger) *Pipeline {
	return &Pipeline{reg: reg, policy: policy, audit: log, cache: cache, log: logger}
}

// Run performs action for the authenticated session p. It returns *Denied
// when the request was refused, and another error when it failed.
func (pl *Pipeline) Run(ctx context.Context, p jobs.Principal, iface, action string, raw json.RawMessage) (connector.Result, error) {
	ev := audit.Event{JobID: p.Job.ID, SessionID: p.SessionID, Interface: iface, Action: action}

	act, spec, params, err := pl.reg.Resolve(action, raw)
	if err != nil {
		reason, recorded := "unknown action", "unknown action"
		if errors.Is(err, connector.ErrInvalidParams) {
			// The validator's message can quote the offending value, so
			// it goes to the agent (who sent it) but not into the audit
			// log, which keeps the params themselves, redacted.
			reason, recorded = err.Error(), "invalid params"
		}
		ev.Params = paramsForAudit(raw)
		if spec, ok := pl.reg.Spec(action); ok {
			ev.Sensitive = spec.Sensitive
		}
		if !actionNameOK(action) {
			ev.Action, ev.Params = "invalid", map[string]any{"requested": truncate(action, 128)}
		}
		return connector.Result{}, pl.denyAs(ctx, ev, "", reason, recorded)
	}
	ev.Params, ev.Sensitive = params, spec.Sensitive

	dec, err := pl.policy.Decide(ctx, Request{Job: p.Job, Interface: iface, Action: action, Spec: spec, Params: params})
	if err != nil {
		return connector.Result{}, pl.deny(ctx, ev, "policy-error", "policy evaluation failed: "+err.Error())
	}
	switch dec.Effect {
	case Allow:
	case RequireApproval:
		// Approvals arrive with #23; until then a parked request fails closed.
		return connector.Result{}, pl.deny(ctx, ev, dec.Rule, "needs approval, and approvals are not available yet")
	case Deny:
		return connector.Result{}, pl.deny(ctx, ev, dec.Rule, dec.Reason)
	default:
		return connector.Result{}, pl.deny(ctx, ev, dec.Rule, fmt.Sprintf("unknown policy effect %q", dec.Effect))
	}

	ev.Decision, ev.Rule = audit.Allow, dec.Rule
	decided, err := pl.audit.Append(ctx, ev)
	if err != nil {
		return connector.Result{}, fmt.Errorf("not recorded, so not done: %w", err)
	}

	result := audit.Event{
		JobID: p.Job.ID, SessionID: p.SessionID, Interface: iface, Action: action, Decision: audit.Info,
		Params: map[string]any{"result_of": decided.Seq},
	}
	c, _ := pl.reg.Connector(act.Connector)
	cred, err := pl.cache.Get(ctx, c, p.Job)
	if err != nil {
		result.Error = err.Error()
		pl.record(ctx, result)
		return connector.Result{}, err
	}
	res, err := c.Execute(ctx, cred, p.Job, act)
	result.UpstreamStatus = res.UpstreamStatus
	if err != nil {
		result.Error = err.Error()
	}
	pl.record(ctx, result)
	return res, err
}

// deny records a refusal and returns it. If the refusal can't be recorded,
// the request still fails, with the audit error.
func (pl *Pipeline) deny(ctx context.Context, ev audit.Event, rule, reason string) error {
	return pl.denyAs(ctx, ev, rule, reason, reason)
}

// denyAs is deny with a different reason for the audit log than for the
// agent.
func (pl *Pipeline) denyAs(ctx context.Context, ev audit.Event, rule, reason, recorded string) error {
	ev.Decision, ev.Rule, ev.Error = audit.Deny, rule, recorded
	if _, err := pl.audit.Append(ctx, ev); err != nil {
		return errors.Join(&Denied{Rule: rule, Reason: reason}, err)
	}
	return &Denied{Rule: rule, Reason: reason}
}

// record writes a result event. The action already happened, so a failure
// here can't undo it; it is logged loudly instead.
func (pl *Pipeline) record(ctx context.Context, ev audit.Event) {
	if _, err := pl.audit.Append(context.WithoutCancel(ctx), ev); err != nil {
		pl.log.Error("an executed action's result was not recorded", "action", ev.Action, "job", ev.JobID, "err", err)
	}
}

// paramsForAudit keeps a refused request's params when they are a JSON
// object (the audit log redacts and truncates them), and otherwise records
// only their size.
func paramsForAudit(raw json.RawMessage) any {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err == nil {
		return m
	}
	return map[string]any{"unparsed_bytes": len(raw)}
}

// auditableName matches what the audit log accepts as an action name.
var auditableName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

func actionNameOK(s string) bool { return auditableName.MatchString(s) }

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
