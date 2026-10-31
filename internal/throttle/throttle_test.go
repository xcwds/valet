package throttle

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestFailure(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := New(3, time.Minute)
	th.now = func() time.Time { return now }

	var got []Verdict
	for range 6 {
		got = append(got, th.Failure("10.0.0.5"))
	}
	want := []Verdict{Record, Record, Record, RecordLimit, Suppress, Suppress}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("verdicts = %v, want %v", got, want)
	}
	if th.Failure("10.0.0.6") != Record {
		t.Error("another source was throttled")
	}
	now = now.Add(time.Minute)
	if th.Failure("10.0.0.5") != Record {
		t.Error("a new window did not reset the count")
	}
}

func TestBoundedMemory(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	th := New(1, time.Minute)
	th.now = func() time.Time { return now }
	for i := range maxSources {
		th.Failure(fmt.Sprint(i))
	}
	if th.Failure("one-too-many") != Suppress {
		t.Error("a new source was admitted past the cap")
	}
	if len(th.sources) > maxSources {
		t.Fatalf("%d sources tracked", len(th.sources))
	}
	now = now.Add(time.Minute) // everything expires
	if th.Failure("fresh") != Record {
		t.Error("expired sources were not pruned")
	}
	if len(th.sources) != 1 {
		t.Errorf("%d sources after pruning, want 1", len(th.sources))
	}
}

func TestSource(t *testing.T) {
	r := &http.Request{RemoteAddr: "172.20.0.3:51234"}
	if Source(r) != "172.20.0.3" {
		t.Errorf("Source = %q", Source(r))
	}
	r.RemoteAddr = "[fd00::3]:443"
	if Source(r) != "fd00::3" {
		t.Errorf("Source = %q", Source(r))
	}
}
