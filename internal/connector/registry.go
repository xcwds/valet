package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

// ErrUnknownAction is returned for an action no connector offers.
var ErrUnknownAction = errors.New("unknown action")

// ErrInvalidParams wraps every params validation failure.
var ErrInvalidParams = errors.New("invalid params")

type entry struct {
	spec     ActionSpec
	resolved *jsonschema.Resolved
}

// Registry holds the connectors valetd was started with.
type Registry struct {
	connectors map[string]Connector
	specs      map[string]entry // by full action name
}

// NewRegistry checks every connector and its catalog: names must be valid
// and unique, and every params schema must resolve. A bad connector stops
// valetd at start rather than failing requests later.
func NewRegistry(cs ...Connector) (*Registry, error) {
	r := &Registry{connectors: map[string]Connector{}, specs: map[string]entry{}}
	for _, c := range cs {
		ns := c.Name()
		if !namespaceRe.MatchString(ns) {
			return nil, fmt.Errorf("connector %q: name must be lowercase letters and digits", ns)
		}
		if _, dup := r.connectors[ns]; dup {
			return nil, fmt.Errorf("connector %q registered twice", ns)
		}
		r.connectors[ns] = c
		for _, s := range c.Actions() {
			if err := validateSpec(ns, s); err != nil {
				return nil, err
			}
			full := ns + "." + s.Name
			if _, dup := r.specs[full]; dup {
				return nil, fmt.Errorf("action %q declared twice", full)
			}
			resolved, err := s.Params.Resolve(nil)
			if err != nil {
				return nil, fmt.Errorf("%s: params schema: %w", full, err)
			}
			r.specs[full] = entry{spec: s, resolved: resolved}
		}
	}
	return r, nil
}

// Connector returns the connector for a namespace.
func (r *Registry) Connector(ns string) (Connector, bool) {
	c, ok := r.connectors[ns]
	return c, ok
}

// Spec returns the spec for a full action name.
func (r *Registry) Spec(full string) (ActionSpec, bool) {
	e, ok := r.specs[full]
	return e.spec, ok
}

// Actions lists every full action name, sorted.
func (r *Registry) Actions() []string {
	out := make([]string, 0, len(r.specs))
	for k := range r.specs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Resolve turns a full action name and raw params into a validated Action,
// its spec and the decoded params (numbers kept exact). Unknown actions and
// params that don't satisfy the schema are errors; the caller denies.
func (r *Registry) Resolve(full string, raw json.RawMessage) (Action, ActionSpec, map[string]any, error) {
	e, ok := r.specs[full]
	if !ok {
		return Action{}, ActionSpec{}, nil, fmt.Errorf("%w: %q", ErrUnknownAction, full)
	}
	ns, name, _ := strings.Cut(full, ".")
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage("{}")
	}
	var instance any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&instance); err != nil {
		return Action{}, ActionSpec{}, nil, fmt.Errorf("%w: not JSON: %s", ErrInvalidParams, err.Error())
	}
	if dec.More() {
		return Action{}, ActionSpec{}, nil, fmt.Errorf("%w: trailing data after the params object", ErrInvalidParams)
	}
	params, ok := instance.(map[string]any)
	if !ok {
		return Action{}, ActionSpec{}, nil, fmt.Errorf("%w: params must be a JSON object", ErrInvalidParams)
	}
	// The validator wants plain JSON values; json.Number isn't one.
	var plain any
	_ = json.Unmarshal(raw, &plain)
	if err := e.resolved.Validate(plain); err != nil {
		return Action{}, ActionSpec{}, nil, fmt.Errorf("%w: %s", ErrInvalidParams, err.Error())
	}
	return Action{Connector: ns, Name: name, Params: raw}, e.spec, params, nil
}
