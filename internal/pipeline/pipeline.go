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

	"github.com/xcwds/valet/internal/alert"
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

// Alerter receives decisions worth telling the operator about (#15). Send
// must not block.
type Alerter interface {
	Send(a alert.Alert)
}

// Pipeline runs requests.
type Pipeline struct {
	reg    *connector.Registry
	policy Policy
	audit  *audit.Log
	cache  *connector.Cache
	log    *slog.Logger
	alerts Alerter
}

// SetAlerter sends denies and alert-rule decisions to a. Set it before
// serving requests.
func (pl *Pipeline) SetAlerter(a Alerter) { pl.alerts = a }

// New returns a Pipeline.
func New(reg *connector.Registry, policy Policy, log *audit.Log, cache *connector.Cache, logger *slog.Logger) *Pipeline {
	return &Pipeline{reg: reg, policy: policy, audit: log, cache: cache, log: logger}
}

// Run performs action for the authenticated session p. It returns *Denied
// when the request was refused, and another error when it failed.
func (pl *Pipeline) Run(ctx context.Context, p jobs.Principal, iface, action string, raw json.RawMessage) (connector.Result, error) {
	ok, err := pl.Authorize(ctx, p, iface, action, raw)
	if err != nil {
		return connector.Result{}, err
	}
	c, _ := pl.reg.Connector(ok.Action.Connector)
	cred, err := ok.Credential(ctx, c)
	if err != nil {
		return connector.Result{}, err
	}
	res, err := c.Execute(ctx, cred, p.Job, ok.Action)
	ok.Done(res.UpstreamStatus, err)
	return res, err
}

// Allowed is an authorized, audited request. Its caller performs it: fetch
// the credential, act, then call Done exactly once with the outcome.
type Allowed struct {
	Action connector.Action
	Params map[string]any // validated

	pl     *Pipeline
	job    jobs.Job
	result audit.Event
	done   bool
}

// Credential mints (or reuses) c's credential for the job. A failure is
// recorded as the request's result, and Done must not be called.
func (a *Allowed) Credential(ctx context.Context, c connector.Connector) (connector.Credential, error) {
	cred, err := a.pl.cache.Get(ctx, c, a.job)
	if err != nil {
		a.Done(0, err)
	}
	return cred, err
}

// Done records the result: the upstream's status and any error.
func (a *Allowed) Done(upstreamStatus int, err error) {
	if a.done {
		return
	}
	a.done = true
	ev := a.result
	ev.UpstreamStatus = upstreamStatus
	if err != nil {
		ev.Error = err.Error()
	}
	a.pl.record(context.Background(), ev)
}

// Authorize runs the pipeline up to the credential: resolve and validate,
// policy, audit the decision. Anything but an allow is recorded and
// returned as *Denied (or the audit error). Interfaces that stream, such as
// the git proxy, use it directly; Run uses it for everything else.
func (pl *Pipeline) Authorize(ctx context.Context, p jobs.Principal, iface, action string, raw json.RawMessage) (*Allowed, error) {
	ev := audit.Event{JobID: p.Job.ID, SessionID: p.SessionID, Interface: iface, Action: action}

	act, spec, params, err := pl.reg.Resolve(action, raw)
	if err == nil && !spec.Available(iface) {
		// Not on this interface: as far as the caller can tell, it
		// doesn't exist.
		err = connector.ErrUnknownAction
	}
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
		return nil, pl.denyAs(ctx, ev, p.Job.Role, "", reason, recorded, false)
	}
	ev.Params, ev.Sensitive = params, spec.Sensitive

	dec, err := pl.policy.Decide(ctx, Request{Job: p.Job, Interface: iface, Action: action, Spec: spec, Params: params})
	role := p.Job.Role
	if err != nil {
		return nil, pl.denyAs(ctx, ev, role, "policy-error", "policy evaluation failed: "+err.Error(), "policy evaluation failed: "+err.Error(), false)
	}
	switch dec.Effect {
	case Allow:
	case RequireApproval:
		// Approvals arrive with #23; until then a parked request fails closed.
		msg := "needs approval, and approvals are not available yet"
		return nil, pl.denyAs(ctx, ev, role, dec.Rule, msg, msg, dec.Alert)
	case Deny:
		return nil, pl.denyAs(ctx, ev, role, dec.Rule, dec.Reason, dec.Reason, dec.Alert)
	default:
		msg := fmt.Sprintf("unknown policy effect %q", dec.Effect)
		return nil, pl.denyAs(ctx, ev, role, dec.Rule, msg, msg, dec.Alert)
	}

	ev.Decision, ev.Rule = audit.Allow, dec.Rule
	decided, err := pl.audit.Append(ctx, ev)
	if err != nil {
		return nil, fmt.Errorf("not recorded, so not done: %w", err)
	}
	if dec.Alert {
		pl.alert(decided, role, dec.Reason, true)
	}
	return &Allowed{
		Action: act, Params: params, pl: pl, job: p.Job,
		result: audit.Event{
			JobID: p.Job.ID, SessionID: p.SessionID, Interface: iface, Action: action, Decision: audit.Info,
			Params: map[string]any{"result_of": decided.Seq},
		},
	}, nil
}

// denyAs records a refusal, offers it to the alerter and returns it, with
// reason for the agent and recorded for the audit log (and the alert). If the
// refusal can't be recorded, the request still fails, with the audit error.
func (pl *Pipeline) denyAs(ctx context.Context, ev audit.Event, role, rule, reason, recorded string, ruleAlert bool) error {
	ev.Decision, ev.Rule, ev.Error = audit.Deny, rule, recorded
	rec, err := pl.audit.Append(ctx, ev)
	if err != nil {
		return errors.Join(&Denied{Rule: rule, Reason: reason}, err)
	}
	pl.alert(rec, role, recorded, ruleAlert)
	return &Denied{Rule: rule, Reason: reason}
}

// alert hands an audited decision to the alerter. It uses the audit
// record's params, which are already redacted and truncated.
func (pl *Pipeline) alert(rec audit.Record, role, reason string, ruleAlert bool) {
	if pl.alerts == nil {
		return
	}
	pl.alerts.Send(alert.Alert{
		JobID: rec.JobID, Role: role, Action: rec.Action, Decision: rec.Decision, Rule: rec.Rule,
		Reason: reason, Params: rec.Params, AuditSeq: rec.Seq, RuleAlert: ruleAlert,
	})
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
