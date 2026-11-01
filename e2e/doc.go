// Package e2e runs the RFC's demo scenarios against a real valetd: the
// daemon in-process with a temporary data directory and generated keys, a
// fake GitHub that records every call, an ntfy sink for alerts, and an MCP
// client holding nothing but a job's session token. No network, no real
// GitHub: `go test ./e2e/...`. Scenarios against a real App live in
// e2e/live and never run in CI.
package e2e
