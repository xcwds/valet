package connector_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/connector/fake"
	"github.com/xcwds/valet/internal/jobs"
)

// stub is a connector with a configurable name and catalog.
type stub struct {
	name  string
	specs []connector.ActionSpec
}

func (s stub) Name() string                    { return s.name }
func (s stub) Actions() []connector.ActionSpec { return s.specs }
func (stub) Mint(context.Context, jobs.Job) (connector.Credential, error) {
	return connector.Credential{}, nil
}

func (stub) Execute(context.Context, connector.Credential, jobs.Job, connector.Action) (connector.Result, error) {
	return connector.Result{}, nil
}

func goodSpec(name string) connector.ActionSpec {
	return connector.ActionSpec{
		Name: name, Description: "d", Risk: connector.RiskLow,
		Params: connector.Object(map[string]*jsonschema.Schema{"repo": {Type: "string"}}, "repo"),
	}
}

func TestRegistryRejectsBadCatalogs(t *testing.T) {
	open := goodSpec("open")
	open.Params = &jsonschema.Schema{Type: "object"} // unknown params allowed
	noDesc := goodSpec("nodesc")
	noDesc.Description = ""
	badRisk := goodSpec("risk")
	badRisk.Risk = "extreme"
	notObject := goodSpec("str")
	notObject.Params = &jsonschema.Schema{Type: "string"}

	cases := map[string][]connector.Connector{
		"duplicate namespace": {stub{name: "x"}, stub{name: "x"}},
		"bad namespace":       {stub{name: "GitHub"}},
		"dotted namespace":    {stub{name: "git.hub"}},
		"duplicate action":    {stub{name: "x", specs: []connector.ActionSpec{goodSpec("a"), goodSpec("a")}}},
		"bad action name":     {stub{name: "x", specs: []connector.ActionSpec{goodSpec("Pr.Comment")}}},
		"open schema":         {stub{name: "x", specs: []connector.ActionSpec{open}}},
		"no description":      {stub{name: "x", specs: []connector.ActionSpec{noDesc}}},
		"bad risk":            {stub{name: "x", specs: []connector.ActionSpec{badRisk}}},
		"non-object schema":   {stub{name: "x", specs: []connector.ActionSpec{notObject}}},
	}
	for name, cs := range cases {
		if _, err := connector.NewRegistry(cs...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := connector.NewRegistry(stub{name: "x", specs: []connector.ActionSpec{goodSpec("pr.comment")}}, &fake.Connector{}); err != nil {
		t.Fatalf("good catalog refused: %v", err)
	}
}

func TestResolve(t *testing.T) {
	reg, err := connector.NewRegistry(&fake.Connector{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(reg.Actions(), ","); got != "fake.danger,fake.echo" {
		t.Errorf("actions = %s", got)
	}
	a, spec, params, err := reg.Resolve("fake.echo", json.RawMessage(`{"message":"hi"}`))
	if err != nil || a.FullName() != "fake.echo" || spec.Risk != connector.RiskLow || params["message"] != "hi" {
		t.Fatalf("Resolve = %+v %+v %v %v", a, spec, params, err)
	}

	if _, _, _, err := reg.Resolve("fake.nope", nil); !errors.Is(err, connector.ErrUnknownAction) {
		t.Errorf("unknown action: %v", err)
	}
	if _, _, _, err := reg.Resolve("github.pr.merge", nil); !errors.Is(err, connector.ErrUnknownAction) {
		t.Errorf("unknown connector: %v", err)
	}
	for _, raw := range []string{
		`{}`,                         // missing required
		`{"message":"hi","extra":1}`, // unknown property
		`{"message":5}`,              // wrong type
		`{"message":"` + strings.Repeat("x", 101) + `"}`, // too long
		`[1]`, `"x"`, `{`, `{"message":"a"} {"message":"b"}`,
	} {
		if _, _, _, err := reg.Resolve("fake.echo", json.RawMessage(raw)); !errors.Is(err, connector.ErrInvalidParams) {
			t.Errorf("Resolve(%.40s) = %v, want ErrInvalidParams", raw, err)
		}
	}
	// No params at all is an empty object, which danger's schema refuses.
	if _, _, _, err := reg.Resolve("fake.danger", nil); !errors.Is(err, connector.ErrInvalidParams) {
		t.Errorf("empty params: %v", err)
	}
}
