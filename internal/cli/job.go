package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/xcwds/valet/internal/jobs"
)

func jobCmd(ctx context.Context, args []string, sys IO) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(sys.Stderr, jobUsage)
		return ExitUsage
	}
	switch args[0] {
	case "create":
		return jobCreateCmd(ctx, args[1:], sys)
	case "list":
		return jobListCmd(ctx, args[1:], sys)
	case "show":
		return jobShowCmd(ctx, args[1:], sys)
	case "revoke":
		return jobRevokeCmd(ctx, args[1:], sys)
	case "enroll":
		return jobEnrollCmd(ctx, args[1:], sys)
	case "-h", "-help", "--help", "help":
		_, _ = fmt.Fprint(sys.Stdout, jobUsage)
		return ExitOK
	default:
		_, _ = fmt.Fprintf(sys.Stderr, "valet job: unknown subcommand %q\n\n%s", args[0], jobUsage)
		return ExitUsage
	}
}

const jobUsage = `Usage: valet job <subcommand> [flags]

Subcommands:
  create --role ROLE [--repo OWNER/NAME ...] [--ttl 1h] [--enroll]
                 Create a job; prints its ID and session token (shown once),
                 or with --enroll a one-time enrollment code for the
                 container to exchange with 'valet session login'
  enroll ID      Issue a new enrollment code, revoking the job's session
  list           List jobs, newest first
  show ID        Show a job
  revoke ID [--reason TEXT]
                 End a job and its sessions now

All talk to valetd's admin API; see 'valet job create -h' for connection flags.
`

func jobCreateCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet job create", sys.Stderr)
	role := fs.String("role", "", "the job's role (required), e.g. reviewer or implementer")
	var repos stringList
	fs.Var(&repos, "repo", "a repository the job may use, owner/name (repeatable)")
	ttl := fs.Duration("ttl", jobs.DefaultTTL, "how long the job lasts")
	enroll := fs.Bool("enroll", false, "print a one-time enrollment code instead of the session token")
	asJSON := fs.Bool("json", false, "print the job and token as JSON")
	conn := addAdminFlags(fs, sys.Getenv)
	if _, code, ok := parseArgs(fs, args, 0); !ok {
		return code
	}
	if *role == "" {
		_, _ = fmt.Fprintln(sys.Stderr, "valet job create: --role is required")
		return ExitUsage
	}
	c, err := conn.client(sys.Getenv)
	if err != nil {
		return fail(sys, "valet job create", err)
	}
	body, _ := json.Marshal(map[string]any{"role": *role, "repos": []string(repos), "ttl": ttl.String(), "enroll": *enroll})
	var resp struct {
		Job        jobs.Job         `json:"job"`
		Token      string           `json:"token,omitempty"`
		Enrollment *jobs.Enrollment `json:"enrollment,omitempty"`
	}
	if err := c.do(ctx, http.MethodPost, "api/jobs", strings.NewReader(string(body)), "application/json", &resp); err != nil {
		return fail(sys, "valet job create", err)
	}
	if *asJSON {
		_ = json.NewEncoder(sys.Stdout).Encode(resp)
		return ExitOK
	}
	_, _ = fmt.Fprintf(sys.Stdout, "job:     %s\nrole:    %s\nrepos:   %s\nbranch:  %s\nexpires: %s\n",
		resp.Job.ID, resp.Job.Role, strings.Join(resp.Job.Repos(), " "), resp.Job.BranchPattern,
		resp.Job.ExpiresAt.Local().Format(time.RFC3339))
	if resp.Enrollment != nil {
		printEnrollment(sys, *resp.Enrollment)
		return ExitOK
	}
	_, _ = fmt.Fprintf(sys.Stdout, "token:   %s\n", resp.Token)
	_, _ = fmt.Fprintln(sys.Stderr, "The token is shown once; give it to the agent and nowhere else.")
	return ExitOK
}

func jobListCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet job list", sys.Stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	conn := addAdminFlags(fs, sys.Getenv)
	if _, code, ok := parseArgs(fs, args, 0); !ok {
		return code
	}
	c, err := conn.client(sys.Getenv)
	if err != nil {
		return fail(sys, "valet job list", err)
	}
	var resp struct {
		Jobs []jobs.Job `json:"jobs"`
	}
	if err := c.do(ctx, http.MethodGet, "api/jobs", nil, "", &resp); err != nil {
		return fail(sys, "valet job list", err)
	}
	if *asJSON {
		_ = json.NewEncoder(sys.Stdout).Encode(resp.Jobs)
		return ExitOK
	}
	tw := tabwriter.NewWriter(sys.Stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tROLE\tSTATE\tEXPIRES\tREPOS")
	for _, j := range resp.Jobs {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", j.ID, j.Role, j.State,
			j.ExpiresAt.Local().Format(time.RFC3339), strings.Join(j.Repos(), " "))
	}
	_ = tw.Flush()
	return ExitOK
}

func jobShowCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet job show", sys.Stderr)
	conn := addAdminFlags(fs, sys.Getenv)
	pos, code, ok := parseArgs(fs, args, 1)
	if !ok {
		return code
	}
	if !jobs.ValidID(pos[0]) {
		_, _ = fmt.Fprintf(sys.Stderr, "valet job show: %q is not a job ID (job-xxxxxxxx)\n", pos[0])
		return ExitUsage
	}
	c, err := conn.client(sys.Getenv)
	if err != nil {
		return fail(sys, "valet job show", err)
	}
	var job jobs.Job
	if err := c.do(ctx, http.MethodGet, "api/jobs/"+pos[0], nil, "", &job); err != nil {
		return fail(sys, "valet job show", err)
	}
	enc := json.NewEncoder(sys.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(job)
	return ExitOK
}

func jobRevokeCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet job revoke", sys.Stderr)
	reason := fs.String("reason", "", "why (recorded in the audit log)")
	conn := addAdminFlags(fs, sys.Getenv)
	pos, code, ok := parseArgs(fs, args, 1)
	if !ok {
		return code
	}
	if !jobs.ValidID(pos[0]) {
		_, _ = fmt.Fprintf(sys.Stderr, "valet job revoke: %q is not a job ID (job-xxxxxxxx)\n", pos[0])
		return ExitUsage
	}
	c, err := conn.client(sys.Getenv)
	if err != nil {
		return fail(sys, "valet job revoke", err)
	}
	body, _ := json.Marshal(map[string]string{"reason": *reason})
	if err := c.do(ctx, http.MethodPost, "api/jobs/"+pos[0]+"/revoke", strings.NewReader(string(body)), "application/json", nil); err != nil {
		return fail(sys, "valet job revoke", err)
	}
	_, _ = fmt.Fprintf(sys.Stdout, "revoked %s\n", pos[0])
	return ExitOK
}

func printEnrollment(sys IO, e jobs.Enrollment) {
	_, _ = fmt.Fprintf(sys.Stdout, "code:    %s\nuse by:  %s\n", e.Code, e.ExpiresAt.Local().Format(time.RFC3339))
	_, _ = fmt.Fprintln(sys.Stderr, "Hand the code to the container as a file (a Docker secret or bind mount), not an env var;"+
		" 'valet session login' exchanges it once for the job's session.")
}

func jobEnrollCmd(ctx context.Context, args []string, sys IO) int {
	fs := newFlagSet("valet job enroll", sys.Stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	conn := addAdminFlags(fs, sys.Getenv)
	pos, code, ok := parseArgs(fs, args, 1)
	if !ok {
		return code
	}
	if !jobs.ValidID(pos[0]) {
		_, _ = fmt.Fprintf(sys.Stderr, "valet job enroll: %q is not a job ID (job-xxxxxxxx)\n", pos[0])
		return ExitUsage
	}
	c, err := conn.client(sys.Getenv)
	if err != nil {
		return fail(sys, "valet job enroll", err)
	}
	var resp struct {
		Enrollment jobs.Enrollment `json:"enrollment"`
	}
	if err := c.do(ctx, http.MethodPost, "api/jobs/"+pos[0]+"/enroll", nil, "", &resp); err != nil {
		return fail(sys, "valet job enroll", err)
	}
	if *asJSON {
		_ = json.NewEncoder(sys.Stdout).Encode(resp)
		return ExitOK
	}
	_, _ = fmt.Fprintf(sys.Stdout, "job:     %s (its previous session is revoked)\n", pos[0])
	printEnrollment(sys, resp.Enrollment)
	return ExitOK
}
