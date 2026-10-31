// Package connector is Hephaestus, the seam between Valet's core and the
// upstreams it brokers (RFC Connector model, decision 7).
//
// A connector owns one upstream: its credentials, its catalog of actions, how
// to execute them and, optionally, how to classify raw proxied requests as
// actions. Core code routes actions to connectors through this package and
// never imports a specific connector; internal/connector/builtin is the one
// place in-tree connectors are listed.
package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/secrets"
)

// Risk is an action's risk level.
type Risk string

// Risk levels.
const (
	RiskLow    Risk = "low"
	RiskMedium Risk = "medium"
	RiskHigh   Risk = "high"
)

// ActionSpec describes one action in a connector's catalog.
type ActionSpec struct {
	// Name within the connector's namespace, e.g. "pr.comment" (the full
	// name is "github.pr.comment").
	Name        string
	Description string
	// Params is the JSON Schema params must satisfy. It is published as the
	// MCP tool's input schema (#14), so it is the contract with agents.
	Params *jsonschema.Schema
	Risk   Risk
	// Sensitive lists top-level params keys the audit log must redact.
	Sensitive []string
}

// Action is a request to perform an action.
type Action struct {
	Connector string
	Name      string          // within the connector, as in ActionSpec.Name
	Params    json.RawMessage // validated against the spec before use
}

// FullName is the action's namespaced name, as policy and audit see it.
func (a Action) FullName() string { return a.Connector + "." + a.Name }

// Credential is an upstream credential minted for one job.
type Credential struct {
	Secret    secrets.Secret
	ExpiresAt time.Time // zero means it doesn't expire on its own
	// Data is connector-private (e.g. which installation a token is for).
	Data any
}

// Result is what an executed action returns to the agent.
type Result struct {
	// UpstreamStatus is the upstream's HTTP status, recorded in the audit
	// log; 0 when there was no HTTP call.
	UpstreamStatus int
	// Body is returned to the agent as JSON. It must never contain a
	// credential (decision 1).
	Body any
}

// Connector is one upstream.
type Connector interface {
	// Name is the action namespace, e.g. "github".
	Name() string
	// Actions returns the catalog.
	Actions() []ActionSpec
	// Mint returns the narrowest credential for the job's grants.
	Mint(ctx context.Context, job jobs.Job) (Credential, error)
	// Execute performs an allowed action with a credential Mint returned.
	Execute(ctx context.Context, cred Credential, job jobs.Job, a Action) (Result, error)
}

// Classifier is implemented by connectors that can map a raw proxied request
// to an action, so proxy traffic is judged in the same terms as MCP calls.
type Classifier interface {
	Classify(r *http.Request, body []byte) (*Action, error)
}

// Revoker is implemented by connectors whose credentials can be revoked
// upstream before they expire. The cache calls it when it drops a credential
// (job revoked or ended).
type Revoker interface {
	Revoke(ctx context.Context, cred Credential) error
}

var (
	namespaceRe = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}$`)
	actionRe    = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,4}$`)
)

func validateSpec(ns string, s ActionSpec) error {
	if !actionRe.MatchString(s.Name) {
		return fmt.Errorf("%s: action name %q: want dot-separated lowercase words", ns, s.Name)
	}
	switch s.Risk {
	case RiskLow, RiskMedium, RiskHigh:
	default:
		return fmt.Errorf("%s.%s: risk %q: want low, medium or high", ns, s.Name, s.Risk)
	}
	if s.Description == "" {
		return fmt.Errorf("%s.%s: needs a description (agents see it)", ns, s.Name)
	}
	if s.Params == nil || s.Params.Type != "object" {
		return fmt.Errorf("%s.%s: params schema must be an object schema", ns, s.Name)
	}
	// Unknown params are refused, so nothing policy didn't see can ride
	// along to the upstream.
	if !isFalse(s.Params.AdditionalProperties) {
		return fmt.Errorf("%s.%s: params schema must set additionalProperties: false (use connector.Object)", ns, s.Name)
	}
	return nil
}

func isFalse(s *jsonschema.Schema) bool {
	return s != nil && s.Not != nil && reflect.ValueOf(*s.Not).IsZero()
}

// Object builds a closed params schema: the given properties, the required
// ones, and nothing else.
func Object(props map[string]*jsonschema.Schema, required ...string) *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:                 "object",
		Properties:           props,
		Required:             required,
		AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}},
	}
}
