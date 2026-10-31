package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
)

// Limits on what an action reads back.
const (
	maxBody     = 65536   // GitHub's limit on an issue, PR or comment body
	maxFileSize = 1 << 20 // repo.file.get
	maxDiffSize = 2 << 20 // pr.diff
)

// Schemas. repo is only accepted in canonical form (lowercase owner/name), so
// a policy rule naming a repository can't be dodged with another spelling:
// GitHub would resolve XCWDS/Prod to xcwds/prod, but policy compares strings.
// Schema constructors: each call returns a fresh schema, because a params
// schema must be a tree (the same node can't appear twice).
func repoSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "string", Pattern: `^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9_-][a-z0-9._-]{0,99}$`,
		Description: "Repository as owner/name, lowercase.",
	}
}

func numberSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "integer", Minimum: ptrF(1), Description: "Issue or pull request number."}
}

func textSchema(desc string) *jsonschema.Schema {
	return &jsonschema.Schema{Type: "string", MinLength: ptr(1), MaxLength: ptr(maxBody), Description: desc}
}

// branchSchema(): a branch in the same repository. No owner: prefix (no
// cross-fork heads); Execute also refuses .. and a trailing / or .lock.
func branchSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "string", Pattern: `^[A-Za-z0-9_][A-Za-z0-9._/-]{0,254}$`, Description: "Branch name in the same repository."}
}

func refSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "string", Pattern: `^[A-Za-z0-9_][A-Za-z0-9._/-]{0,254}$`, Description: "Branch, tag or commit SHA."}
}

func pathSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "string", Pattern: `^[^/\x00][^\x00]*$`, MaxLength: ptr(1024), Description: "File path in the repository, without a leading /."}
}

func ptr(n int) *int          { return &n }
func ptrF(n float64) *float64 { return &n }

func props(kv ...any) map[string]*jsonschema.Schema {
	m := map[string]*jsonschema.Schema{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1].(*jsonschema.Schema)
	}
	return m
}

// Actions implements connector.Connector: the v1 catalog (RFC GitHub
// connector).
func (*Connector) Actions() []connector.ActionSpec {
	return []connector.ActionSpec{
		{
			Name: "repo.read", Risk: connector.RiskLow, Description: "Read a repository's metadata.",
			Params: connector.Object(props("repo", repoSchema()), "repo"),
		},
		{
			Name: "repo.file.get", Risk: connector.RiskLow, Description: "Read one file from a repository (up to 1 MiB).",
			Params: connector.Object(props("repo", repoSchema(), "path", pathSchema(), "ref", refSchema()), "repo", "path"),
		},
		{
			Name: "issue.read", Risk: connector.RiskLow, Description: "Read an issue.",
			Params: connector.Object(props("repo", repoSchema(), "number", numberSchema()), "repo", "number"),
		},
		{
			Name: "issue.comment", Risk: connector.RiskMedium, Description: "Comment on an issue.",
			Params: connector.Object(props("repo", repoSchema(), "number", numberSchema(), "body", textSchema("Comment text (Markdown).")), "repo", "number", "body"),
		},
		{
			Name: "pr.read", Risk: connector.RiskLow, Description: "Read a pull request.",
			Params: connector.Object(props("repo", repoSchema(), "number", numberSchema()), "repo", "number"),
		},
		{
			Name: "pr.diff", Risk: connector.RiskLow, Description: "Read a pull request's diff (up to 2 MiB).",
			Params: connector.Object(props("repo", repoSchema(), "number", numberSchema()), "repo", "number"),
		},
		{
			Name: "pr.create", Risk: connector.RiskMedium, Description: "Open a pull request from a branch in the same repository.",
			Params: connector.Object(props("repo", repoSchema(), "head", branchSchema(), "base", branchSchema(),
				"title", &jsonschema.Schema{Type: "string", MinLength: ptr(1), MaxLength: ptr(256)},
				"body", &jsonschema.Schema{Type: "string", MaxLength: ptr(maxBody)},
				"draft", &jsonschema.Schema{Type: "boolean"}), "repo", "head", "base", "title"),
		},
		{
			Name: "pr.comment", Risk: connector.RiskMedium, Description: "Comment on a pull request's conversation.",
			Params: connector.Object(props("repo", repoSchema(), "number", numberSchema(), "body", textSchema("Comment text (Markdown).")), "repo", "number", "body"),
		},
		{
			Name: "pr.review.submit", Risk: connector.RiskHigh, Description: "Submit a review on a pull request.",
			Params: connector.Object(props("repo", repoSchema(), "number", numberSchema(),
				"event", &jsonschema.Schema{Type: "string", Enum: []any{"COMMENT", "REQUEST_CHANGES", "APPROVE"}},
				"body", &jsonschema.Schema{Type: "string", MaxLength: ptr(maxBody)},
				"comments", &jsonschema.Schema{Type: "array", MaxItems: ptr(100), Items: connector.Object(props(
					"path", pathSchema(),
					"line", &jsonschema.Schema{Type: "integer", Minimum: ptrF(1)},
					"side", &jsonschema.Schema{Type: "string", Enum: []any{"LEFT", "RIGHT"}},
					"body", textSchema("Comment text."),
				), "path", "line", "body")}), "repo", "number", "event"),
		},
		{
			Name: "pr.merge", Risk: connector.RiskHigh, Description: "Merge a pull request.",
			Params: connector.Object(props("repo", repoSchema(), "number", numberSchema(),
				"method", &jsonschema.Schema{Type: "string", Enum: []any{"merge", "squash", "rebase"}},
				"sha", &jsonschema.Schema{Type: "string", Pattern: `^[0-9a-f]{40}$`, Description: "Merge only if the head is still this commit."}),
				"repo", "number"),
		},
		{
			Name: "checks.read", Risk: connector.RiskLow, Description: "Read the check runs for a ref.",
			Params: connector.Object(props("repo", repoSchema(), "ref", refSchema()), "repo", "ref"),
		},
	}
}

// params is what every action decodes; each uses the fields it declares.
type params struct {
	Repo     string          `json:"repo"`
	Number   int             `json:"number"`
	Path     string          `json:"path"`
	Ref      string          `json:"ref"`
	Body     *string         `json:"body"`
	Head     string          `json:"head"`
	Base     string          `json:"base"`
	Title    string          `json:"title"`
	Draft    bool            `json:"draft"`
	Event    string          `json:"event"`
	Comments json.RawMessage `json:"comments"`
	Method   string          `json:"method"`
	SHA      string          `json:"sha"`
}

// Execute implements connector.Connector. Every result is a curated set of
// fields, never GitHub's raw objects, so nothing the agent sees can carry a
// credential or more than the action is for.
func (c *Connector) Execute(ctx context.Context, cred connector.Credential, _ jobs.Job, a connector.Action) (connector.Result, error) {
	var p params
	if err := json.Unmarshal(a.Params, &p); err != nil {
		return connector.Result{}, fmt.Errorf("github: params: %w", err)
	}
	// Belt and braces behind the schema: the repo must be exactly its
	// canonical form, so what policy compared is what GitHub resolves.
	if n, err := jobs.NormalizeRepo(p.Repo); err != nil || n != p.Repo {
		return connector.Result{}, fmt.Errorf("github: repository %q is not in canonical owner/name form", p.Repo)
	}
	for _, s := range []string{p.Head, p.Base, p.Ref} {
		if strings.Contains(s, "..") || strings.HasSuffix(s, "/") || strings.HasSuffix(s, ".lock") {
			return connector.Result{}, fmt.Errorf("github: invalid ref name %q", s)
		}
	}
	x := exec{c: c, ctx: ctx, auth: "Bearer " + string(cred.Secret.Reveal()), repo: "/repos/" + p.Repo}
	switch a.Name {
	case "repo.read":
		return x.repoRead()
	case "repo.file.get":
		return x.fileGet(p)
	case "issue.read":
		return x.issueRead(p)
	case "issue.comment", "pr.comment":
		return x.comment(p)
	case "pr.read":
		return x.prRead(p)
	case "pr.diff":
		return x.prDiff(p)
	case "pr.create":
		return x.prCreate(p)
	case "pr.review.submit":
		return x.reviewSubmit(p)
	case "pr.merge":
		return x.merge(p)
	case "checks.read":
		return x.checksRead(p)
	}
	return connector.Result{}, fmt.Errorf("github: no executor for %s", a.Name)
}

type exec struct {
	c    *Connector
	ctx  context.Context
	auth string
	repo string // /repos/owner/name
}

// json makes a JSON call and decodes the answer into out.
func (x exec) json(method, path string, body any, want int, out any) (int, error) {
	var b []byte
	if body != nil {
		var err error
		if b, err = json.Marshal(body); err != nil {
			return 0, err
		}
	}
	status, data, _, err := x.c.send(x.ctx, method, x.repo+path, x.auth, "application/vnd.github+json", b, 4<<20)
	if err != nil {
		return 0, err
	}
	if status != want {
		return status, apiError(status, data)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return status, fmt.Errorf("github: unexpected answer: %w", err)
		}
	}
	return status, nil
}

func result(status int, body any, err error) (connector.Result, error) {
	return connector.Result{UpstreamStatus: status, Body: body}, err
}

func (x exec) repoRead() (connector.Result, error) {
	var r struct {
		FullName      string `json:"full_name"`
		Description   string `json:"description"`
		DefaultBranch string `json:"default_branch"`
		Private       bool   `json:"private"`
		Archived      bool   `json:"archived"`
		HTMLURL       string `json:"html_url"`
	}
	status, err := x.json(http.MethodGet, "", nil, http.StatusOK, &r)
	if err != nil {
		return result(status, nil, err)
	}
	return result(status, map[string]any{
		"full_name": r.FullName, "description": r.Description, "default_branch": r.DefaultBranch,
		"private": r.Private, "archived": r.Archived, "url": r.HTMLURL,
	}, nil)
}

// escapePath escapes each segment of a repository path, refusing . and ..
// segments so the request can't climb out of the contents endpoint.
func escapePath(p string) (string, error) {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if s == "" || s == "." || s == ".." {
			return "", fmt.Errorf("github: invalid path %q", p)
		}
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/"), nil
}

func (x exec) fileGet(p params) (connector.Result, error) {
	path, err := escapePath(p.Path)
	if err != nil {
		return connector.Result{}, err
	}
	q := ""
	if p.Ref != "" {
		q = "?ref=" + url.QueryEscape(p.Ref)
	}
	var f struct {
		Type     string `json:"type"`
		Path     string `json:"path"`
		SHA      string `json:"sha"`
		Size     int    `json:"size"`
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	status, err := x.json(http.MethodGet, "/contents/"+path+q, nil, http.StatusOK, &f)
	if err != nil {
		if errors.As(err, new(*APIError)) {
			return result(status, nil, err)
		}
		// A directory answers with a JSON array.
		return result(status, nil, fmt.Errorf("github: %s is not a file", p.Path))
	}
	if f.Type != "file" {
		return result(status, nil, fmt.Errorf("github: %s is a %s, not a file", p.Path, f.Type))
	}
	if f.Size > maxFileSize || f.Encoding != "base64" {
		return result(status, map[string]any{"path": f.Path, "sha": f.SHA, "size": f.Size, "too_large": true}, nil)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(f.Content, "\n", ""))
	if err != nil {
		return result(status, nil, fmt.Errorf("github: file content: %w", err))
	}
	out := map[string]any{"path": f.Path, "sha": f.SHA, "size": f.Size}
	if utf8.Valid(raw) {
		out["content"], out["encoding"] = string(raw), "utf-8"
	} else {
		out["content"], out["encoding"] = base64.StdEncoding.EncodeToString(raw), "base64"
	}
	return result(status, out, nil)
}

type ghUser struct {
	Login string `json:"login"`
}

func (x exec) issueRead(p params) (connector.Result, error) {
	var i struct {
		Number   int     `json:"number"`
		Title    string  `json:"title"`
		State    string  `json:"state"`
		Body     *string `json:"body"`
		User     ghUser  `json:"user"`
		Comments int     `json:"comments"`
		Labels   []struct {
			Name string `json:"name"`
		} `json:"labels"`
		PullRequest *struct{} `json:"pull_request"`
		HTMLURL     string    `json:"html_url"`
	}
	status, err := x.json(http.MethodGet, fmt.Sprintf("/issues/%d", p.Number), nil, http.StatusOK, &i)
	if err != nil {
		return result(status, nil, err)
	}
	labels := []string{}
	for _, l := range i.Labels {
		labels = append(labels, l.Name)
	}
	return result(status, map[string]any{
		"number": i.Number, "title": i.Title, "state": i.State, "body": deref(i.Body), "author": i.User.Login,
		"labels": labels, "comments": i.Comments, "is_pull_request": i.PullRequest != nil, "url": i.HTMLURL,
	}, nil)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (x exec) comment(p params) (connector.Result, error) {
	var c struct {
		ID      int64  `json:"id"`
		HTMLURL string `json:"html_url"`
	}
	status, err := x.json(http.MethodPost, fmt.Sprintf("/issues/%d/comments", p.Number), map[string]string{"body": deref(p.Body)}, http.StatusCreated, &c)
	if err != nil {
		return result(status, nil, err)
	}
	return result(status, map[string]any{"id": c.ID, "url": c.HTMLURL}, nil)
}

func (x exec) prRead(p params) (connector.Result, error) {
	var pr struct {
		Number    int     `json:"number"`
		Title     string  `json:"title"`
		State     string  `json:"state"`
		Body      *string `json:"body"`
		User      ghUser  `json:"user"`
		Draft     bool    `json:"draft"`
		Merged    bool    `json:"merged"`
		Mergeable *bool   `json:"mergeable"`
		Head      struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
		HTMLURL string `json:"html_url"`
	}
	status, err := x.json(http.MethodGet, fmt.Sprintf("/pulls/%d", p.Number), nil, http.StatusOK, &pr)
	if err != nil {
		return result(status, nil, err)
	}
	return result(status, map[string]any{
		"number": pr.Number, "title": pr.Title, "state": pr.State, "body": deref(pr.Body), "author": pr.User.Login,
		"draft": pr.Draft, "merged": pr.Merged, "mergeable": pr.Mergeable,
		"head": pr.Head.Ref, "head_sha": pr.Head.SHA, "base": pr.Base.Ref, "url": pr.HTMLURL,
	}, nil)
}

func (x exec) prDiff(p params) (connector.Result, error) {
	status, data, truncated, err := x.c.send(x.ctx, http.MethodGet, fmt.Sprintf("%s/pulls/%d", x.repo, p.Number), x.auth, "application/vnd.github.diff", nil, maxDiffSize)
	if err != nil {
		return result(status, nil, err)
	}
	if status != http.StatusOK {
		return result(status, nil, apiError(status, data))
	}
	return result(status, map[string]any{"diff": string(data), "truncated": truncated}, nil)
}

func (x exec) prCreate(p params) (connector.Result, error) {
	req := map[string]any{"head": p.Head, "base": p.Base, "title": p.Title, "draft": p.Draft}
	if p.Body != nil {
		req["body"] = *p.Body
	}
	var pr struct {
		Number  int    `json:"number"`
		HTMLURL string `json:"html_url"`
	}
	status, err := x.json(http.MethodPost, "/pulls", req, http.StatusCreated, &pr)
	if err != nil {
		return result(status, nil, err)
	}
	return result(status, map[string]any{"number": pr.Number, "url": pr.HTMLURL}, nil)
}

func (x exec) reviewSubmit(p params) (connector.Result, error) {
	req := map[string]any{"event": p.Event}
	if p.Body != nil {
		req["body"] = *p.Body
	}
	if len(p.Comments) > 0 {
		req["comments"] = p.Comments
	}
	var r struct {
		ID    int64  `json:"id"`
		State string `json:"state"`
	}
	status, err := x.json(http.MethodPost, fmt.Sprintf("/pulls/%d/reviews", p.Number), req, http.StatusOK, &r)
	if err != nil {
		return result(status, nil, err)
	}
	return result(status, map[string]any{"id": r.ID, "state": r.State}, nil)
}

func (x exec) merge(p params) (connector.Result, error) {
	req := map[string]any{}
	if p.Method != "" {
		req["merge_method"] = p.Method
	}
	if p.SHA != "" {
		req["sha"] = p.SHA
	}
	var m struct {
		SHA    string `json:"sha"`
		Merged bool   `json:"merged"`
	}
	status, err := x.json(http.MethodPut, fmt.Sprintf("/pulls/%d/merge", p.Number), req, http.StatusOK, &m)
	if err != nil {
		return result(status, nil, err)
	}
	return result(status, map[string]any{"merged": m.Merged, "sha": m.SHA}, nil)
}

func (x exec) checksRead(p params) (connector.Result, error) {
	var r struct {
		Total int `json:"total_count"`
		Runs  []struct {
			Name       string  `json:"name"`
			Status     string  `json:"status"`
			Conclusion *string `json:"conclusion"`
			HTMLURL    string  `json:"html_url"`
		} `json:"check_runs"`
	}
	status, err := x.json(http.MethodGet, "/commits/"+url.PathEscape(p.Ref)+"/check-runs?per_page=100", nil, http.StatusOK, &r)
	if err != nil {
		return result(status, nil, err)
	}
	runs := []map[string]any{}
	for _, run := range r.Runs {
		runs = append(runs, map[string]any{"name": run.Name, "status": run.Status, "conclusion": deref(run.Conclusion), "url": run.HTMLURL})
	}
	return result(status, map[string]any{"total": r.Total, "check_runs": runs}, nil)
}
