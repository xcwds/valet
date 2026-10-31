package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xcwds/valet/internal/config"
	"github.com/xcwds/valet/internal/logging"
)

func testConfig() *config.Config {
	return &config.Config{
		DataDir: "/unused",
		Listen:  config.Listen{Admin: "127.0.0.1:0", Agent: "127.0.0.1:0", Egress: "127.0.0.1:0"},
	}
}

// syncBuffer is a bytes.Buffer safe for the daemon's goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// start runs the daemon and returns its addresses and a stop function that
// cancels it and returns Run's error.
func start(t *testing.T, cfg *config.Config, logs io.Writer) (Addrs, func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	readyc := make(chan Addrs, 1)
	errc := make(chan error, 1)
	go func() {
		errc <- Run(ctx, cfg, logging.New(logs, "json", slog.LevelDebug), func(a Addrs) { readyc <- a })
	}()
	select {
	case a := <-readyc:
		stopped := false
		stop := func() error {
			if stopped {
				return nil
			}
			stopped = true
			cancel()
			select {
			case err := <-errc:
				return err
			case <-time.After(ShutdownTimeout + 5*time.Second):
				t.Fatal("Run did not return after cancel")
				return nil
			}
		}
		t.Cleanup(func() { _ = stop() })
		return a, stop
	case err := <-errc:
		cancel()
		t.Fatalf("Run failed before ready: %v", err)
		return Addrs{}, nil
	}
}

// get returns the status code and body of a GET.
func get(t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestHealthz(t *testing.T) {
	addrs, stop := start(t, testConfig(), io.Discard)

	status, body := get(t, "http://"+addrs.Admin+"/healthz")
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil || got["status"] != "ok" || got["version"] == "" {
		t.Fatalf("body = %q (%v)", body, err)
	}
	if err := stop(); err != nil {
		t.Fatalf("Run returned %v after a requested stop, want nil", err)
	}
}

func TestHealthzOnlyOnAdmin(t *testing.T) {
	addrs, _ := start(t, testConfig(), io.Discard)
	for _, a := range []string{addrs.Agent, addrs.Egress} {
		if status, _ := get(t, "http://"+a+"/healthz"); status != http.StatusForbidden {
			t.Errorf("%s/healthz status = %d, want 403", a, status)
		}
	}
	if status, _ := get(t, "http://"+addrs.Admin+"/nope"); status != http.StatusNotFound {
		t.Errorf("admin /nope status = %d, want 404", status)
	}
}

func TestAgentAndEgressRefuseEverything(t *testing.T) {
	addrs, _ := start(t, testConfig(), io.Discard)

	if status, _ := get(t, "http://"+addrs.Agent+"/mcp"); status != http.StatusForbidden {
		t.Errorf("agent /mcp status = %d, want 403", status)
	}

	// A CONNECT through the egress port must not open a tunnel.
	conn, err := net.Dial("tcp", addrs.Egress)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("CONNECT status = %d, want 403", resp.StatusCode)
	}
}

func TestLogsStartAndStop(t *testing.T) {
	var logs syncBuffer
	_, stop := start(t, testConfig(), &logs)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	for _, want := range []string{`"msg":"started"`, `"msg":"stopping"`, `"msg":"stopped"`, `"component":"valetd"`} {
		if !strings.Contains(out, want) {
			t.Errorf("logs missing %s:\n%s", want, out)
		}
	}
}

func TestPortInUse(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	cfg := testConfig()
	cfg.Listen.Egress = busy.Addr().String()
	err = Run(context.Background(), cfg, logging.New(io.Discard, "json", slog.LevelInfo), func(Addrs) {
		t.Error("ready called although a listener failed")
	})
	if err == nil || !strings.Contains(err.Error(), "listen egress") {
		t.Fatalf("err = %v, want a listen egress error", err)
	}
}

func TestShutdownClosesIdleConnections(t *testing.T) {
	addrs, stop := start(t, testConfig(), io.Discard)

	// Hold a keep-alive connection open; Shutdown must close idle
	// connections and return promptly rather than wait for the idle timeout.
	conn, err := net.Dial("tcp", addrs.Admin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	done := make(chan error, 1)
	go func() { done <- stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown waited on an idle keep-alive connection")
	}
}

func TestInFlightRequestFinishesDuringShutdown(t *testing.T) {
	// A handler that respects its context must keep running after the stop
	// signal, within the grace period.
	entered := make(chan struct{})
	release := make(chan struct{})
	ctxErr := make(chan error, 1)
	testAdminHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		ctxErr <- r.Context().Err()
		_, _ = w.Write([]byte("done"))
	})
	t.Cleanup(func() { testAdminHandler = nil })

	addrs, stop := start(t, testConfig(), io.Discard)
	respc := make(chan int, 1)
	go func() {
		status, _ := get(t, "http://"+addrs.Admin+"/slow")
		respc <- status
	}()
	<-entered

	stopErr := make(chan error, 1)
	go func() { stopErr <- stop() }() // what SIGTERM does
	time.Sleep(100 * time.Millisecond)
	close(release)

	if err := <-ctxErr; err != nil {
		t.Errorf("request context was canceled by the stop signal: %v", err)
	}
	if status := <-respc; status != http.StatusOK {
		t.Errorf("status = %d, want 200", status)
	}
	if err := <-stopErr; err != nil {
		t.Fatal(err)
	}
}
