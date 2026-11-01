// Package mcp is Iris, Valet's MCP endpoint (RFC Architecture): one
// streamable-HTTP endpoint at /mcp on the agent port that offers every
// connector's actions as tools and runs every call through the pipeline.
//
// It is stateless: each POST gets a server built for the session that sent
// it, so a tool call always acts as the token on that request, never as
// whichever token opened an earlier MCP session.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/logging"
	"github.com/xcwds/valet/internal/pipeline"
	"github.com/xcwds/valet/internal/version"
)

// Interface is the audit interface name for MCP calls.
const Interface = "mcp"

// Offerer decides which actions a role is offered as tools; the policy
// implements it. Without one, every action is offered.
type Offerer interface {
	MayAllow(role, action string) bool
}

// Runner runs an action; the pipeline implements it.
type Runner interface {
	Run(ctx context.Context, p jobs.Principal, iface, action string, raw json.RawMessage) (connector.Result, error)
}

// Iris serves MCP.
type Iris struct {
	reg     *connector.Registry
	run     Runner
	offer   Offerer
	log     *slog.Logger
	tools   map[string]string // tool name → action
	actions map[string]string // action → tool name
}

// ToolName is an action's MCP tool name: its dots become underscores
// (github.pr.comment → github_pr_comment). Anthropic's API, and so Claude
// Code, only accepts [a-zA-Z0-9_-] in tool names.
func ToolName(action string) string { return strings.ReplaceAll(action, ".", "_") }

// New returns Iris over the registry's actions. Two actions whose tool names
// collide (a.b_c and a.b.c) are refused, so a tool name always means one
// action.
func New(reg *connector.Registry, run Runner, offer Offerer, log *slog.Logger) (*Iris, error) {
	i := &Iris{reg: reg, run: run, offer: offer, log: logging.For(log, logging.Iris), tools: map[string]string{}, actions: map[string]string{}}
	for _, a := range reg.Actions() {
		name := ToolName(a)
		if other, dup := i.tools[name]; dup {
			return nil, fmt.Errorf("mcp: actions %s and %s would both be tool %s", other, a, name)
		}
		i.tools[name], i.actions[a] = a, name
	}
	return i, nil
}

// Handler serves MCP. It must sit behind jobs.RequireSession, which puts
// the caller's session in the request context.
func (i *Iris) Handler() http.Handler {
	return sdk.NewStreamableHTTPHandler(i.serverFor, &sdk.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
		Logger:       i.log,
	})
}

// serverFor builds the MCP server for one request, offering the tools the
// session's role could use.
func (i *Iris) serverFor(r *http.Request) *sdk.Server {
	p, ok := jobs.PrincipalFrom(r.Context())
	if !ok {
		return nil // RequireSession didn't run: refuse
	}
	srv := sdk.NewServer(&sdk.Implementation{Name: "valet", Version: version.String()}, &sdk.ServerOptions{
		Instructions: fmt.Sprintf("Valet brokers your access for job %s (role %s). Every call is checked against policy and audited; "+
			"a denied call returns an error naming the rule.", p.Job.ID, p.Job.Role),
	})
	actions := i.reg.Actions()
	sort.Strings(actions)
	for _, a := range actions {
		spec, _ := i.reg.Spec(a)
		if !spec.Available(Interface) {
			continue // e.g. git.push: only the git proxy may ask
		}
		if i.offer != nil && !i.offer.MayAllow(p.Job.Role, a) {
			continue
		}
		action := a
		srv.AddTool(&sdk.Tool{
			Name:        i.actions[a],
			Description: fmt.Sprintf("%s (Valet action %s, risk %s)", spec.Description, a, spec.Risk),
			InputSchema: spec.Params,
		}, func(ctx context.Context, req *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return i.call(ctx, p, action, req.Params.Arguments), nil
		})
	}
	// Every tools/call goes through the pipeline, including tools this role
	// wasn't offered: probing is denied and audited, not just "unknown".
	srv.AddReceivingMiddleware(func(next sdk.MethodHandler) sdk.MethodHandler {
		return func(ctx context.Context, method string, req sdk.Request) (sdk.Result, error) {
			if method != "tools/call" {
				return next(ctx, method, req)
			}
			params, ok := req.GetParams().(*sdk.CallToolParamsRaw)
			if !ok {
				return next(ctx, method, req)
			}
			action, known := i.tools[params.Name]
			if !known {
				action = params.Name // the pipeline denies and audits it as unknown
			}
			return i.call(ctx, p, action, params.Arguments), nil
		}
	})
	return srv
}

// call runs one action and turns the outcome into a tool result. A denial
// names the rule; any other failure is reported without upstream detail,
// which is in the audit log.
func (i *Iris) call(ctx context.Context, p jobs.Principal, action string, args json.RawMessage) *sdk.CallToolResult {
	res, err := i.run.Run(ctx, p, Interface, action, args)
	var denied *pipeline.Denied
	switch {
	case errors.As(err, &denied):
		return errorResult(denied.Error())
	case err != nil:
		i.log.Warn("action failed", "job", p.Job.ID, "action", action, "upstream_status", res.UpstreamStatus, "err", err)
		msg := "the action failed; the details are in Valet's audit log"
		if res.UpstreamStatus != 0 {
			msg = fmt.Sprintf("the action failed: the upstream answered HTTP %d (details are in Valet's audit log)", res.UpstreamStatus)
		}
		return errorResult(msg)
	}
	body, err := json.Marshal(res.Body)
	if err != nil {
		return errorResult("the action's result could not be encoded")
	}
	out := &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: string(body)}}}
	if json.Valid(body) && len(body) > 0 && body[0] == '{' {
		out.StructuredContent = json.RawMessage(body)
	}
	return out
}

func errorResult(msg string) *sdk.CallToolResult {
	return &sdk.CallToolResult{IsError: true, Content: []sdk.Content{&sdk.TextContent{Text: msg}}}
}
