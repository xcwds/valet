// Package policies holds Valet's default roles. valetd uses them when the
// config sets no policies path; copy them as a starting point for your own.
package policies

import "embed"

// Defaults are the default role files.
//
//go:embed *.yaml
var Defaults embed.FS
