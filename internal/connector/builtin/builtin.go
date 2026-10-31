// Package builtin lists the in-tree connectors valetd starts with. It is the
// only package outside a connector's own directory allowed to import one, so
// adding a connector touches its directory and this list, never core code
// (RFC decision 7).
package builtin

import "github.com/xcwds/valet/internal/connector"

// All returns the in-tree connectors. GitHub joins with #12.
func All() []connector.Connector {
	return nil
}
