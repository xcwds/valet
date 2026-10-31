// Package fake is a connector for tests: it records what the pipeline asks
// of it and can be told to fail.
package fake

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/jobs"
	"github.com/xcwds/valet/internal/secrets"
)

// Connector is the fake. Its namespace is "fake".
type Connector struct {
	mu        sync.Mutex
	Mints     []string // job IDs minted for
	Executed  []string // full action names executed
	Revoked   []string // credential values revoked
	MintErr   error
	ExecErr   error
	CredTTL   time.Duration // 0: credentials don't expire on their own
	MintDelay time.Duration
	n         int
}

// Name implements connector.Connector.
func (*Connector) Name() string { return "fake" }

// Actions implements connector.Connector: "echo" (low risk; takes a message
// and an optional note, which its spec marks sensitive) and "danger".
func (*Connector) Actions() []connector.ActionSpec {
	return []connector.ActionSpec{
		{
			Name:        "echo",
			Description: "Echo a message back.",
			Risk:        connector.RiskLow,
			Params: connector.Object(map[string]*jsonschema.Schema{
				"message": {Type: "string", MaxLength: ptr(100)},
				"note":    {Type: "string"},
			}, "message"),
			Sensitive: []string{"note"},
		},
		{
			Name:        "danger",
			Description: "Something policy should stop.",
			Risk:        connector.RiskHigh,
			Params:      connector.Object(map[string]*jsonschema.Schema{"target": {Type: "string"}}, "target"),
		},
	}
}

func ptr(n int) *int { return &n }

// Mint implements connector.Connector.
func (f *Connector) Mint(ctx context.Context, job jobs.Job) (connector.Credential, error) {
	if f.MintDelay > 0 {
		select {
		case <-time.After(f.MintDelay):
		case <-ctx.Done():
			return connector.Credential{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.MintErr != nil {
		return connector.Credential{}, f.MintErr
	}
	f.n++
	f.Mints = append(f.Mints, job.ID)
	cred := connector.Credential{Secret: secrets.NewSecret([]byte(fmt.Sprintf("fake-cred-%d", f.n)))}
	if f.CredTTL > 0 {
		cred.ExpiresAt = time.Now().Add(f.CredTTL)
	}
	return cred, nil
}

// Execute implements connector.Connector.
func (f *Connector) Execute(_ context.Context, cred connector.Credential, job jobs.Job, a connector.Action) (connector.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Executed = append(f.Executed, a.FullName())
	if f.ExecErr != nil {
		return connector.Result{UpstreamStatus: 502}, f.ExecErr
	}
	var p map[string]any
	if err := json.Unmarshal(a.Params, &p); err != nil {
		return connector.Result{}, errors.New("params")
	}
	// The credential is checked, never returned.
	_ = cred.Secret.Reveal()
	return connector.Result{UpstreamStatus: 200, Body: map[string]any{"echo": p["message"], "job": job.ID}}, nil
}

// Revoke implements connector.Revoker.
func (f *Connector) Revoke(_ context.Context, cred connector.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Revoked = append(f.Revoked, string(cred.Secret.Reveal()))
	return nil
}

// Snapshot returns copies of the recorded calls.
func (f *Connector) Snapshot() (mints, executed, revoked []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Mints...), append([]string(nil), f.Executed...), append([]string(nil), f.Revoked...)
}
