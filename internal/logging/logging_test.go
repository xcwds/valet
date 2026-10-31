package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestJSONHasComponentField(t *testing.T) {
	var buf bytes.Buffer
	For(New(&buf, "json", slog.LevelInfo), Themis).Info("deny", "rule", 2)

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("not JSON: %q", buf.String())
	}
	if rec["component"] != "themis" || rec["msg"] != "deny" || rec["rule"] != float64(2) {
		t.Fatalf("record = %v", rec)
	}
}

func TestTextPrefixesMessage(t *testing.T) {
	var buf bytes.Buffer
	For(New(&buf, "text", slog.LevelInfo), Themis).Info("deny: reviewer may not APPROVE", "job", "job-42")

	out := buf.String()
	if !strings.Contains(out, `msg="[themis] deny: reviewer may not APPROVE"`) {
		t.Errorf("no prefix in %q", out)
	}
	if !strings.Contains(out, "job=job-42") {
		t.Errorf("attribute lost in %q", out)
	}
	if strings.Contains(out, "component=") {
		t.Errorf("component repeated as a field in %q", out)
	}
}

func TestTextWithoutComponent(t *testing.T) {
	var buf bytes.Buffer
	New(&buf, "text", slog.LevelInfo).Info("hello")
	if !strings.Contains(buf.String(), "msg=hello") {
		t.Errorf("got %q", buf.String())
	}
}

func TestTextInnermostComponentWins(t *testing.T) {
	var buf bytes.Buffer
	l := For(For(New(&buf, "text", slog.LevelInfo), Valetd), Clio)
	l.WithGroup("g").Info("x", "a", 1)
	if !strings.Contains(buf.String(), `msg="[clio] x"`) || !strings.Contains(buf.String(), "g.a=1") {
		t.Errorf("got %q", buf.String())
	}
}

func TestLevel(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "json", slog.LevelWarn)
	l.Info("quiet")
	if buf.Len() != 0 {
		t.Errorf("info logged at warn level: %q", buf.String())
	}
	l.Warn("loud")
	if buf.Len() == 0 {
		t.Error("warn not logged")
	}
}
