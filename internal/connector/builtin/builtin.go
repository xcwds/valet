// Package builtin lists the in-tree connectors valetd starts with. It is the
// only package outside a connector's own directory allowed to import one, so
// adding a connector touches its directory and this list, never core code
// (RFC decision 7).
package builtin

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"

	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/connector/github"
)

// File is the connectors file: one optional section per connector. A
// connector whose section is absent isn't started.
type File struct {
	GitHub *github.Config `yaml:"github"`
}

// Deps are what connectors may need from valetd.
type Deps struct {
	Secrets github.SecretGetter
}

// Load reads the connectors file at path (none if path is empty) and builds
// the connectors it configures. Parsing is strict: an unknown connector or
// key is an error.
func Load(path string, deps Deps) ([]connector.Connector, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // The operator chooses the path.
	if err != nil {
		return nil, fmt.Errorf("connectors: %w", err)
	}
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("connectors %s: %w", path, err)
	}
	var out []connector.Connector
	if f.GitHub != nil {
		c, err := github.New(*f.GitHub, deps.Secrets)
		if err != nil {
			return nil, fmt.Errorf("connectors %s: %w", path, err)
		}
		out = append(out, c)
	}
	return out, nil
}
