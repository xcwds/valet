package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/pipeline"
)

// policyCmd: valet policy check. It runs the policy offline, without
// valetd, so an operator can try a rule before deploying it.
func policyCmd(ctx context.Context, args []string, sys IO) int {
	if len(args) == 0 || args[0] != "check" {
		_, _ = fmt.Fprint(sys.Stderr, policyUsage)
		return ExitUsage
	}
	fs := newFlagSet("valet policy check", sys.Stderr)
	path := fs.String("policies", sys.Getenv("VALET_POLICIES"), "policy file or directory (default $VALET_POLICIES, else the built-in roles)")
	role := fs.String("role", "", "the job's role (required)")
	action := fs.String("action", "", "full action name, e.g. github.pr.review.submit (required)")
	params := fs.String("params", "{}", "the action's params as JSON")
	jobID := fs.String("job", "job-aaaaaaaa", "job ID (rules can refer to job.id)")
	var repos stringList
	fs.Var(&repos, "repo", "a repository the job may use (repeatable)")
	fs.Usage = func() {
		_, _ = fmt.Fprint(fs.Output(), policyUsage+"\nFlags:\n")
		fs.PrintDefaults()
	}
	if _, code, ok := parseArgs(fs, args[1:], 0); !ok {
		return code
	}
	if *role == "" || *action == "" {
		_, _ = fmt.Fprintln(sys.Stderr, "valet policy check: --role and --action are required")
		return ExitUsage
	}
	pol, err := loadPolicy(*path)
	if err != nil {
		return fail(sys, "valet policy check", err)
	}
	var ps map[string]any
	dec := json.NewDecoder(bytes.NewReader([]byte(*params)))
	dec.UseNumber()
	if err := dec.Decode(&ps); err != nil {
		_, _ = fmt.Fprintf(sys.Stderr, "valet policy check: --params: %v\n", err)
		return ExitUsage
	}
	var normalized []string
	for _, r := range repos {
		n, err := jobs.NormalizeRepo(r)
		if err != nil {
			_, _ = fmt.Fprintf(sys.Stderr, "valet policy check: %v\n", err)
			return ExitUsage
		}
		normalized = append(normalized, n)
	}
	job := jobs.Job{
		ID: *jobID, Role: *role, BranchPattern: "agent/" + *jobID + "/*", ExpiresAt: time.Now().Add(time.Hour),
		Grants: jobs.Grants{GitHub: &jobs.GitHubGrant{Repos: normalized}},
	}
	d, err := pol.Decide(ctx, pipeline.Request{
		Job: job, Interface: "mcp", Action: *action, Params: ps,
		Spec: connector.ActionSpec{Params: &jsonschema.Schema{}},
	})
	if err != nil {
		return fail(sys, "valet policy check", err)
	}
	alert := ""
	if d.Alert {
		alert = " (alert)"
	}
	_, _ = fmt.Fprintf(sys.Stdout, "%s%s\nrule:   %s\nreason: %s\n", strings.ToUpper(d.Effect), alert, d.Rule, d.Reason)
	return ExitOK
}

const policyUsage = `Usage: valet policy check --role ROLE --action ACTION [--params JSON] [--repo O/N ...] [--policies PATH]

Shows what the policy decides for one request, and which rule decided.
Params are not validated against the action's schema here (valetd does that
first), so pass them in the shape the connector expects.
`
