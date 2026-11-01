package gitproxy

import (
	"context"
	"errors"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/xcwds/valet/internal/audit"
	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
)

// Namespace is the git actions' namespace: git.fetch and git.push.
const Namespace = "git"

// Actions is the catalog of the generic git actions. They are requested
// only by the git proxy, which mints with the provider's connector; the
// registry holds them so policy, validation and audit treat them like
// every other action.
type Actions struct{}

var errProxyOnly = errors.New("git actions run only through the git proxy")

// Name implements connector.Connector.
func (Actions) Name() string { return Namespace }

// Mint implements connector.Connector; the provider's connector mints.
func (Actions) Mint(context.Context, jobs.Job) (connector.Credential, error) {
	return connector.Credential{}, errProxyOnly
}

// Execute implements connector.Connector; the proxy executes.
func (Actions) Execute(context.Context, connector.Credential, jobs.Job, connector.Action) (connector.Result, error) {
	return connector.Result{}, errProxyOnly
}

// Actions implements connector.Connector.
func (Actions) Actions() []connector.ActionSpec {
	only := []string{audit.InterfaceGit}
	return []connector.ActionSpec{
		{
			Name: "fetch", Risk: connector.RiskLow, Interfaces: only,
			Description: "Clone or fetch a repository (and the ref advertisement before a push).",
			Params:      connector.Object(map[string]*jsonschema.Schema{"provider": providerSchema(), "repo": repoSchema()}, "provider", "repo"),
		},
		{
			Name: "push", Risk: connector.RiskHigh, Interfaces: only,
			Description: "Push ref updates to a repository.",
			Params: connector.Object(map[string]*jsonschema.Schema{
				"provider": providerSchema(),
				"repo":     repoSchema(),
				"refs": {
					Type: "array", MinItems: ptr(1), MaxItems: ptr(MaxRefs),
					Items: connector.Object(map[string]*jsonschema.Schema{
						"name":   {Type: "string", MinLength: ptr(6), MaxLength: ptr(1024), Pattern: "^refs/"},
						"old":    shaSchema(),
						"new":    shaSchema(),
						"delete": {Type: "boolean"},
					}, "name", "old", "new", "delete"),
				},
			}, "provider", "repo", "refs"),
		},
	}
}

func providerSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "string", Pattern: `^[a-z][a-z0-9]{0,31}$`}
}

func repoSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "string", MaxLength: ptr(200), Pattern: `^[a-z0-9][a-z0-9._-]*/[a-z0-9._-]+$`}
}

func shaSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "string", Pattern: `^([0-9a-f]{40}|[0-9a-f]{64})$`}
}

func ptr(n int) *int { return &n }
