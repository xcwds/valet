package connector_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/connector/fake"
	"github.com/xcwds/valet/internal/jobs"
)

var ctx = context.Background()

func job(id string, ttl time.Duration) jobs.Job {
	return jobs.Job{ID: id, ExpiresAt: time.Now().Add(ttl)}
}

func TestCacheMintsOncePerJob(t *testing.T) {
	f := &fake.Connector{MintDelay: 20 * time.Millisecond}
	c := connector.NewCache()
	j := job("job-aaaaaaaa", time.Hour)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(ctx, f, j); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	mints, _, _ := f.Snapshot()
	if len(mints) != 1 {
		t.Fatalf("%d mints for 20 concurrent requests, want 1", len(mints))
	}
	if _, err := c.Get(ctx, f, job("job-bbbbbbbb", time.Hour)); err != nil {
		t.Fatal(err)
	}
	if mints, _, _ := f.Snapshot(); len(mints) != 2 {
		t.Errorf("another job reused a credential: %v", mints)
	}
}

func TestCacheRefreshesBeforeExpiry(t *testing.T) {
	f := &fake.Connector{CredTTL: connector.RefreshBefore + time.Minute}
	c := connector.NewCache()
	j := job("job-aaaaaaaa", time.Hour)
	first, _ := c.Get(ctx, f, j)
	again, _ := c.Get(ctx, f, j)
	if string(first.Secret.Reveal()) != string(again.Secret.Reveal()) {
		t.Fatal("a fresh credential was replaced")
	}
	f.CredTTL = connector.RefreshBefore - time.Second // next mint is near expiry already
	c2 := connector.NewCache()
	_, _ = c2.Get(ctx, f, j)
	_, _ = c2.Get(ctx, f, j)
	if mints, _, _ := f.Snapshot(); len(mints) != 3 {
		t.Errorf("mints = %d, want a near-expiry credential to be replaced", len(mints))
	}
}

func TestCacheNeverOutlivesTheJob(t *testing.T) {
	f := &fake.Connector{}
	c := connector.NewCache()
	if _, err := c.Get(ctx, f, job("job-aaaaaaaa", -time.Second)); !errors.Is(err, connector.ErrJobEnded) {
		t.Fatalf("expired job: %v", err)
	}
	// A job ending within the refresh window gets a new mint each time,
	// never a cached credential past the job's end.
	j := job("job-bbbbbbbb", time.Minute)
	_, _ = c.Get(ctx, f, j)
	_, _ = c.Get(ctx, f, j)
	if mints, _, _ := f.Snapshot(); len(mints) != 2 {
		t.Errorf("mints = %d", len(mints))
	}
}

func TestDropJobRevokes(t *testing.T) {
	f := &fake.Connector{}
	reg, _ := connector.NewRegistry(f)
	c := connector.NewCache()
	cred, _ := c.Get(ctx, f, job("job-aaaaaaaa", time.Hour))
	_, _ = c.Get(ctx, f, job("job-bbbbbbbb", time.Hour))
	if err := c.DropJob(ctx, reg, "job-aaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	_, _, revoked := f.Snapshot()
	if len(revoked) != 1 || revoked[0] != string(cred.Secret.Reveal()) {
		t.Fatalf("revoked = %v", revoked)
	}
	if c.Len() != 1 {
		t.Errorf("cache holds %d entries, want only the other job's", c.Len())
	}
}

func TestSweep(t *testing.T) {
	f := &fake.Connector{CredTTL: time.Hour}
	c := connector.NewCache()
	_, _ = c.Get(ctx, f, job("job-aaaaaaaa", time.Hour))
	f.MintErr = errors.New("down")
	_, _ = c.Get(ctx, f, job("job-bbbbbbbb", time.Hour)) // failed mint leaves an invalid entry
	if n := c.Sweep(); n != 1 || c.Len() != 1 {
		t.Fatalf("swept %d, %d left; want the failed entry gone and the live one kept", n, c.Len())
	}
}

func TestNoMintAfterDrop(t *testing.T) {
	// A request authenticated before the revocation reaches the cache after
	// it: it must not mint for the revoked job.
	f := &fake.Connector{}
	reg, _ := connector.NewRegistry(f)
	c := connector.NewCache()
	j := job("job-aaaaaaaa", time.Hour)
	if err := c.DropJob(ctx, reg, j.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(ctx, f, j); !errors.Is(err, connector.ErrJobEnded) {
		t.Fatalf("Get after drop = %v, want ErrJobEnded", err)
	}
	if mints, _, _ := f.Snapshot(); len(mints) != 0 {
		t.Fatalf("minted for a revoked job: %v", mints)
	}
}

func TestDropDuringMint(t *testing.T) {
	f := &fake.Connector{MintDelay: 100 * time.Millisecond}
	reg, _ := connector.NewRegistry(f)
	c := connector.NewCache()
	j := job("job-aaaaaaaa", time.Hour)
	errc := make(chan error, 1)
	go func() {
		_, err := c.Get(ctx, f, j)
		errc <- err
	}()
	time.Sleep(20 * time.Millisecond) // mint in flight
	if err := c.DropJob(ctx, reg, j.ID); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; !errors.Is(err, connector.ErrJobEnded) {
		t.Fatalf("Get across a drop = %v, want ErrJobEnded", err)
	}
	if _, _, revoked := f.Snapshot(); len(revoked) != 1 {
		t.Errorf("the credential minted across the drop was not revoked: %v", revoked)
	}
}
