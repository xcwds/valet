package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStatusHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","version":"v9"}`))
	}))
	defer srv.Close()

	code, stdout, stderr := run(t, context.Background(), nil, "valet", "status", "--addr", srv.URL)
	if code != ExitOK || !strings.Contains(stdout, "valetd v9") || !strings.Contains(stdout, "ok") {
		t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestStatusAddrFromEnvAndBasePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/valet/healthz" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","version":"v9"}`))
	}))
	defer srv.Close()

	code, _, stderr := run(t, context.Background(), map[string]string{"VALET_ADMIN_URL": srv.URL + "/valet/"}, "valet", "status")
	if code != ExitOK {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestStatusUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	code, stdout, stderr := run(t, context.Background(), nil, "valet", "status", "--addr", srv.URL)
	if code != ExitError || stdout != "" || !strings.Contains(stderr, "unhealthy") {
		t.Fatalf("code %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

func TestStatusUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	code, _, stderr := run(t, context.Background(), nil, "valet", "status", "--addr", url)
	if code != ExitError || !strings.Contains(stderr, "not reachable") {
		t.Fatalf("code %d, stderr %q", code, stderr)
	}
}

func TestStatusBadAddr(t *testing.T) {
	for _, addr := range []string{"localhost:14400", "ftp://x", "http://", "http://user:pw@x", "http://x/?q=1"} {
		code, _, stderr := run(t, context.Background(), nil, "valet", "status", "--addr", addr)
		if code != ExitUsage || !strings.Contains(stderr, "--addr") {
			t.Errorf("--addr %q: code %d, stderr %q", addr, code, stderr)
		}
	}
}
