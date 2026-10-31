package connector

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/xcwds/valet/internal/jobs"
)

// RefreshBefore is how long before expiry a cached credential is replaced.
const RefreshBefore = 5 * time.Minute

// ErrJobEnded is returned when a job was revoked or ended while its
// credential was being minted.
var ErrJobEnded = errors.New("job ended")

type cacheKey struct{ job, connector string }

type cacheEntry struct {
	mu        sync.Mutex // held while minting, so one mint per key at a time
	cred      Credential
	expiresAt time.Time
	valid     bool
}

// Cache holds minted credentials per job and connector. A credential lives
// no longer than its own expiry or its job's, and is dropped (and revoked
// upstream, where the connector can) when the job is revoked.
type Cache struct {
	mu      sync.Mutex
	entries map[cacheKey]*cacheEntry
	now     func() time.Time
}

// NewCache returns an empty cache.
func NewCache() *Cache {
	return &Cache{entries: map[cacheKey]*cacheEntry{}, now: time.Now}
}

// Get returns a credential for job from c, minting one if none is cached or
// the cached one is about to expire.
func (k *Cache) Get(ctx context.Context, c Connector, job jobs.Job) (Credential, error) {
	key := cacheKey{job.ID, c.Name()}
	k.mu.Lock()
	e, ok := k.entries[key]
	if !ok {
		e = &cacheEntry{}
		k.entries[key] = e
	}
	k.mu.Unlock()

	e.mu.Lock()
	defer e.mu.Unlock()
	now := k.now()
	if e.valid && now.Add(RefreshBefore).Before(e.expiresAt) {
		return e.cred, nil
	}
	if !now.Before(job.ExpiresAt) {
		return Credential{}, ErrJobEnded
	}
	cred, err := c.Mint(ctx, job)
	if err != nil {
		e.valid = false
		return Credential{}, fmt.Errorf("mint %s credential: %w", c.Name(), err)
	}
	// If the job was dropped while minting, this credential must not be
	// used or kept: revoke it and fail the request.
	k.mu.Lock()
	current := k.entries[key] == e
	k.mu.Unlock()
	if !current {
		if r, ok := c.(Revoker); ok {
			_ = r.Revoke(context.WithoutCancel(ctx), cred)
		}
		return Credential{}, ErrJobEnded
	}
	exp := job.ExpiresAt
	if !cred.ExpiresAt.IsZero() && cred.ExpiresAt.Before(exp) {
		exp = cred.ExpiresAt
	}
	e.cred, e.expiresAt, e.valid = cred, exp, true
	return cred, nil
}

// DropJob forgets every credential minted for jobID and revokes each
// upstream where the connector supports it. reg finds the connectors.
func (k *Cache) DropJob(ctx context.Context, reg *Registry, jobID string) error {
	k.mu.Lock()
	var dropped []struct {
		ns string
		e  *cacheEntry
	}
	for key, e := range k.entries {
		if key.job == jobID {
			delete(k.entries, key)
			dropped = append(dropped, struct {
				ns string
				e  *cacheEntry
			}{key.connector, e})
		}
	}
	k.mu.Unlock()

	var errs []error
	for _, d := range dropped {
		d.e.mu.Lock() // wait out an in-flight mint; it will see the drop
		cred, valid := d.e.cred, d.e.valid
		d.e.valid = false
		d.e.mu.Unlock()
		if !valid {
			continue
		}
		c, ok := reg.Connector(d.ns)
		if !ok {
			continue
		}
		if r, ok := c.(Revoker); ok {
			if err := r.Revoke(ctx, cred); err != nil {
				errs = append(errs, fmt.Errorf("revoke %s credential for %s: %w", d.ns, jobID, err))
			}
		}
	}
	return errors.Join(errs...)
}

// Sweep forgets credentials whose job or credential has expired. They are
// already unusable; this only bounds memory. valetd runs it periodically.
func (k *Cache) Sweep() int {
	now := k.now()
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for key, e := range k.entries {
		if !e.mu.TryLock() {
			continue // minting right now; leave it
		}
		if !e.valid || !now.Before(e.expiresAt) {
			delete(k.entries, key)
			n++
		}
		e.mu.Unlock()
	}
	return n
}

// Len is the number of cached entries, for tests and metrics.
func (k *Cache) Len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.entries)
}
