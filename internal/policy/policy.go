// Package policy is Themis, Valet's policy engine (RFC Policy engine,
// decision 5).
//
// Policy is a set of roles; a role is an ordered list of rules. A rule
// matches an action pattern and, optionally, a CEL condition over the action,
// its params and the job; its decision is allow, deny or require_approval.
// The first matching rule decides. No match, an unknown role, or any error
// while evaluating is a deny. Every condition is compiled and type-checked
// when policy loads, so a broken rule stops valetd instead of failing
// requests.
package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/ext"
	"go.yaml.in/yaml/v3"

	"github.com/xcwds/valet/internal/pipeline"
)

// Limits on evaluating one condition.
const (
	CostLimit   = 100_000
	EvalTimeout = 100 * time.Millisecond
)

// Job is what a condition sees as `job`.
type Job struct {
	ID            string    `cel:"id"`
	Role          string    `cel:"role"`
	Repos         []string  `cel:"repos"`
	BranchPattern string    `cel:"branch_pattern"`
	CreatedBy     string    `cel:"created_by"`
	ExpiresAt     time.Time `cel:"expires_at"`
}

// Action is what a condition sees as `action`.
type Action struct {
	Name      string `cel:"name"`
	Connector string `cel:"connector"`
	Risk      string `cel:"risk"`
	Interface string `cel:"interface"`
}

// File is one YAML document: a role.
type File struct {
	Role        string     `yaml:"role"`
	Description string     `yaml:"description"`
	Rules       []RuleSpec `yaml:"rules"`
}

// RuleSpec is a rule as written.
type RuleSpec struct {
	Name     string `yaml:"name"`
	Action   string `yaml:"action"`
	When     string `yaml:"when"`
	Decision string `yaml:"decision"`
	Reason   string `yaml:"reason"`
	Alert    bool   `yaml:"alert"`
}

type rule struct {
	id      string // name, or role#n (1-based)
	pattern string
	match   *regexp.Regexp
	when    string
	prg     cel.Program // nil: always true
	effect  string
	reason  string
	alert   bool
}

type role struct {
	name        string
	description string
	rules       []rule
}

// Policy is a loaded, compiled set of roles. It is safe for concurrent use.
type Policy struct {
	roles  map[string]*role
	source string
}

var roleName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// newEnv is the CEL environment every condition compiles in.
func newEnv() (*cel.Env, error) {
	return cel.NewEnv(
		ext.NativeTypes(reflect.TypeFor[Job](), reflect.TypeFor[Action](), ext.ParseStructTags(true)),
		cel.Variable("job", cel.ObjectType("policy.Job")),
		cel.Variable("action", cel.ObjectType("policy.Action")),
		cel.Variable("params", cel.MapType(cel.StringType, cel.DynType)),
		ext.Strings(),
	)
}

// Source says where the policy came from, for logs.
func (p *Policy) Source() string { return p.source }

// Roles lists the role names, sorted.
func (p *Policy) Roles() []string {
	out := make([]string, 0, len(p.roles))
	for n := range p.roles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// HasRole reports whether a role is defined; job creation uses it.
func (p *Policy) HasRole(name string) bool {
	_, ok := p.roles[name]
	return ok
}

// LoadPath loads a YAML file, or every *.yaml and *.yml file in a directory.
func LoadPath(path string) (*Policy, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if !info.IsDir() {
		b, err := os.ReadFile(path) //nolint:gosec // The operator chooses the policy path.
		if err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
		return Load(path, map[string][]byte{filepath.Base(path): b})
	}
	return LoadFS(path, os.DirFS(path))
}

// LoadFS loads every *.yaml and *.yml file at the top of fsys.
func LoadFS(source string, fsys fs.FS) (*Policy, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	files := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yaml") && !strings.HasSuffix(e.Name(), ".yml")) {
			continue
		}
		b, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
		files[e.Name()] = b
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("policy: no .yaml files in %s", source)
	}
	return Load(source, files)
}

// Load parses and compiles the given files (name → contents). Every problem
// is reported at once.
func Load(source string, files map[string][]byte) (*Policy, error) {
	env, err := newEnv()
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p := &Policy{roles: map[string]*role{}, source: source}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var errs []error
	for _, name := range names {
		dec := yaml.NewDecoder(bytes.NewReader(files[name]))
		dec.KnownFields(true)
		for doc := 1; ; doc++ {
			var f File
			err := dec.Decode(&f)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s (document %d): %w", name, doc, err))
				break
			}
			r, rerrs := compileRole(env, f)
			for _, e := range rerrs {
				errs = append(errs, fmt.Errorf("%s (document %d): %w", name, doc, e))
			}
			if r == nil {
				continue
			}
			if _, dup := p.roles[r.name]; dup {
				errs = append(errs, fmt.Errorf("%s: role %q is defined twice", name, r.name))
				continue
			}
			p.roles[r.name] = r
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("policy: %w", errors.Join(errs...))
	}
	if len(p.roles) == 0 {
		return nil, errors.New("policy: no roles defined")
	}
	return p, nil
}

func compileRole(env *cel.Env, f File) (*role, []error) {
	if !roleName.MatchString(f.Role) {
		return nil, []error{fmt.Errorf("role %q: want lowercase letters, digits and -", f.Role)}
	}
	if len(f.Rules) == 0 {
		return nil, []error{fmt.Errorf("role %s: no rules", f.Role)}
	}
	r := &role{name: f.Role, description: f.Description}
	var errs []error
	ids := map[string]bool{}
	for i, spec := range f.Rules {
		id := fmt.Sprintf("%s#%d", f.Role, i+1)
		if spec.Name != "" {
			id = f.Role + "/" + spec.Name
		}
		if ids[id] {
			errs = append(errs, fmt.Errorf("rule %s: name used twice", id))
			continue
		}
		ids[id] = true
		ru := rule{id: id, pattern: spec.Action, when: spec.When, effect: spec.Decision, reason: spec.Reason, alert: spec.Alert}
		switch spec.Decision {
		case pipeline.Allow, pipeline.Deny, pipeline.RequireApproval:
		default:
			errs = append(errs, fmt.Errorf("rule %s: decision %q: want allow, deny or require_approval", id, spec.Decision))
			continue
		}
		re, err := compilePattern(spec.Action)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %s: %w", id, err))
			continue
		}
		ru.match = re
		if strings.TrimSpace(spec.When) != "" {
			ast, iss := env.Compile(spec.When)
			if iss.Err() != nil {
				errs = append(errs, fmt.Errorf("rule %s: when: %w", id, iss.Err()))
				continue
			}
			if t := ast.OutputType(); !t.IsExactType(types.BoolType) && !t.IsExactType(types.DynType) {
				errs = append(errs, fmt.Errorf("rule %s: when must be a boolean expression, not %s", id, t))
				continue
			}
			prg, err := env.Program(ast, cel.CostLimit(CostLimit), cel.InterruptCheckFrequency(100))
			if err != nil {
				errs = append(errs, fmt.Errorf("rule %s: when: %w", id, err))
				continue
			}
			ru.prg = prg
		}
		r.rules = append(r.rules, ru)
	}
	return r, errs
}

// Decide implements pipeline.Policy: the first rule of the job's role whose
// pattern and condition match decides; otherwise deny.
func (p *Policy) Decide(ctx context.Context, req pipeline.Request) (pipeline.Decision, error) {
	r, ok := p.roles[req.Job.Role]
	if !ok {
		return pipeline.Decision{Effect: pipeline.Deny, Rule: "default", Reason: fmt.Sprintf("role %q is not defined", req.Job.Role)}, nil
	}
	vars := map[string]any{
		"job": Job{
			ID: req.Job.ID, Role: req.Job.Role, Repos: append([]string{}, req.Job.Repos()...),
			BranchPattern: req.Job.BranchPattern, CreatedBy: req.Job.CreatedBy, ExpiresAt: req.Job.ExpiresAt,
		},
		"action": Action{Name: req.Action, Connector: connectorOf(req.Action), Risk: string(req.Spec.Risk), Interface: req.Interface},
		"params": celValue(req.Params),
	}
	for _, ru := range r.rules {
		if !ru.match.MatchString(req.Action) {
			continue
		}
		if ru.prg != nil {
			matched, err := eval(ctx, ru.prg, vars)
			if err != nil {
				// Fail closed: an error in a rule that applies is a deny,
				// never a fall-through to a later, more permissive rule.
				// CEL's message can quote params (a regex error quotes the
				// pattern), so it goes in Detail, which is never audited.
				return pipeline.Decision{Effect: pipeline.Deny, Rule: ru.id, Reason: "condition could not be evaluated", Detail: err.Error()}, nil
			}
			if !matched {
				continue
			}
		}
		reason := ru.reason
		if reason == "" {
			reason = fmt.Sprintf("%s by rule %s", ru.effect, ru.id)
		}
		return pipeline.Decision{Effect: ru.effect, Rule: ru.id, Reason: reason, Alert: ru.alert}, nil
	}
	return pipeline.Decision{Effect: pipeline.Deny, Rule: "default", Reason: fmt.Sprintf("no rule in role %s allows %s", r.name, req.Action)}, nil
}

func connectorOf(action string) string {
	c, _, _ := strings.Cut(action, ".")
	return c
}

func eval(ctx context.Context, prg cel.Program, vars map[string]any) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, EvalTimeout)
	defer cancel()
	out, _, err := prg.ContextEval(ctx, vars)
	if err != nil {
		return false, err
	}
	b, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("condition returned %s, not a boolean", out.Type())
	}
	return b, nil
}

// MayAllow reports whether role has a rule that could allow action (or ask
// for approval), ignoring conditions. The MCP endpoint lists only such
// actions, so an agent isn't offered tools that always deny; calling one it
// wasn't offered still goes through policy, and is denied and audited.
func (p *Policy) MayAllow(role, action string) bool {
	r, ok := p.roles[role]
	if !ok {
		return false
	}
	for _, ru := range r.rules {
		if ru.match.MatchString(action) && ru.effect != pipeline.Deny {
			return true
		}
	}
	return false
}

// Unmatched lists rule patterns that match none of the given action names,
// for a start-up warning: a typo in a pattern silently denies.
func (p *Policy) Unmatched(actions []string) []string {
	var out []string
	for _, rn := range p.Roles() {
		for _, ru := range p.roles[rn].rules {
			hit := false
			for _, a := range actions {
				if ru.match.MatchString(a) {
					hit = true
					break
				}
			}
			if !hit {
				out = append(out, ru.id+" ("+ru.pattern+")")
			}
		}
	}
	return out
}
