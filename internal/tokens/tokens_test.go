package tokens

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewParses(t *testing.T) {
	for _, k := range []Kind{Session, Admin, Enroll} {
		tok, hash, err := New(k)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(tok, "vlt_") || !strings.HasPrefix(tok, string(k)) {
			t.Errorf("token %q lacks prefix %q", tok, k)
		}
		got, err := Parse(k, tok)
		if err != nil || !bytes.Equal(got, hash) {
			t.Errorf("Parse(%q) = %x, %v", tok, got, err)
		}
	}
}

func TestTokensAreDistinct(t *testing.T) {
	a, _, _ := New(Session)
	b, _, _ := New(Session)
	if a == b {
		t.Fatal("two tokens are equal")
	}
}

func TestKindsDoNotCross(t *testing.T) {
	sess, _, _ := New(Session)
	admin, _, _ := New(Admin)
	if _, err := Parse(Admin, sess); err == nil {
		t.Error("a session token parsed as an admin token")
	}
	if _, err := Parse(Session, admin); err == nil {
		t.Error("an admin token parsed as a session token")
	}
}

func TestMalformed(t *testing.T) {
	good, _, _ := New(Session)
	for _, tok := range []string{
		"", "vlt_sess_", good + "a", good[:len(good)-1], strings.ToUpper(good),
		"vlt_sess_" + strings.Repeat("1", 52), "Bearer " + good, " " + good, good + "\n",
		"ghp_" + strings.Repeat("a", 36),
	} {
		if _, err := Parse(Session, tok); err == nil {
			t.Errorf("Parse(%q) accepted", tok)
		}
	}
}
