package gitproxy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

var (
	sha1  = strings.Repeat("a", 40)
	sha2  = strings.Repeat("b", 40)
	zeros = strings.Repeat("0", 40)
)

func TestParseCommands(t *testing.T) {
	body := pkt("shallow "+sha1+"\n") +
		pkt(sha1+" "+sha2+" refs/heads/agent/job-1/x\x00report-status side-band-64k push-options agent=git/2.43\n") +
		pkt(zeros+" "+sha2+" refs/heads/agent/job-1/new\n") +
		pkt(sha1+" "+zeros+" refs/heads/agent/job-1/old\n") +
		"0000" +
		pkt("ci.skip\n") + "0000" + // push options: after the flush, untouched
		"PACK\x00\x00\x00\x02rest-of-pack"
	r := strings.NewReader(body)
	c, err := ParseCommands(r)
	if err != nil {
		t.Fatal(err)
	}
	want := []RefUpdate{
		{"refs/heads/agent/job-1/x", sha1, sha2, false},
		{"refs/heads/agent/job-1/new", zeros, sha2, false},
		{"refs/heads/agent/job-1/old", sha1, zeros, true},
	}
	if len(c.Refs) != 3 || c.Refs[0] != want[0] || c.Refs[1] != want[1] || c.Refs[2] != want[2] {
		t.Errorf("refs = %+v", c.Refs)
	}
	if !c.HasCap("report-status") || !c.HasCap("side-band-64k") || !c.HasCap("agent") || c.HasCap("atomic") {
		t.Errorf("caps = %v", c.Caps)
	}
	rest, _ := io.ReadAll(r)
	if string(c.Raw)+string(rest) != body {
		t.Error("raw prefix plus the unread rest is not the original body")
	}
	if !strings.HasPrefix(string(rest), pkt("ci.skip\n")) {
		t.Errorf("read past the flush: rest = %q", rest)
	}
}

func TestParseCommandsSHA256(t *testing.T) {
	a, b := strings.Repeat("c", 64), strings.Repeat("d", 64)
	c, err := ParseCommands(strings.NewReader(pkt(a+" "+b+" refs/heads/x\x00object-format=sha256") + "0000"))
	if err != nil || c.Refs[0].New != b {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := ParseCommands(strings.NewReader(pkt(sha1+" "+b+" refs/heads/x\x00") + "0000")); err == nil {
		t.Error("mixed hash lengths accepted")
	}
}

func TestParseCommandsRefuses(t *testing.T) {
	cmd := func(ref string) string { return pkt(sha1+" "+sha2+" "+ref+"\x00report-status") + "0000" }
	cases := map[string]string{
		"empty body":            "",
		"only flush":            "0000",
		"truncated header":      "00",
		"truncated payload":     "0040" + sha1,
		"no flush":              pkt(sha1 + " " + sha2 + " refs/heads/x\x00"),
		"non-hex length":        "zzzz",
		"signed length":         "+040",
		"delim packet":          "0001",
		"response-end packet":   "0002",
		"empty packet":          "0004",
		"over 65520":            "fff1",
		"uppercase sha":         pkt(strings.ToUpper(sha1)+" "+sha2+" refs/heads/x\x00") + "0000",
		"short sha":             pkt("abc "+sha2+" refs/heads/x\x00") + "0000",
		"zero to zero":          pkt(zeros+" "+zeros+" refs/heads/x\x00") + "0000",
		"extra field":           pkt(sha1+" "+sha2+" refs/heads/x extra\x00") + "0000",
		"NUL in second command": pkt(sha1+" "+sha2+" refs/heads/x\x00caps") + pkt(sha1+" "+sha2+" refs/heads/y\x00more") + "0000",
		"push certificate":      pkt("push-cert\x00report-status") + "0000",
		"shallow after command": pkt(sha1+" "+sha2+" refs/heads/x\x00") + pkt("shallow "+sha1) + "0000",
		"bad shallow":           pkt("shallow nope") + "0000",
		"not under refs/":       cmd("HEAD"),
		"dot dot":               cmd("refs/heads/agent/job-1/../../main"),
		"double slash":          cmd("refs/heads//main"),
		"trailing slash":        cmd("refs/heads/x/"),
		"trailing dot":          cmd("refs/heads/x."),
		"dot component":         cmd("refs/heads/.hidden"),
		"lock suffix":           cmd("refs/heads/x.lock"),
		"at brace":              cmd("refs/heads/x@{1}"),
		"space":                 cmd("refs/heads/a b"),
		"colon":                 cmd("refs/heads/a:b"),
		"glob":                  cmd("refs/heads/a*"),
		"control char":          cmd("refs/heads/a\tb"),
		"backslash":             cmd(`refs/heads/a\b`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if c, err := ParseCommands(strings.NewReader(body)); !errors.Is(err, ErrMalformed) {
				t.Errorf("accepted: %+v %v", c, err)
			}
		})
	}
}

func TestParseCommandsLimits(t *testing.T) {
	var b strings.Builder
	for i := range MaxRefs + 1 {
		b.WriteString(pkt(sha1 + " " + sha2 + " refs/heads/r" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + "\n"))
	}
	b.WriteString("0000")
	if _, err := ParseCommands(strings.NewReader(b.String())); !errors.Is(err, ErrMalformed) {
		t.Errorf("more than MaxRefs accepted: %v", err)
	}

	// One long line after another until the byte cap: refused without
	// reading the rest of an endless body.
	long := pkt(sha1 + " " + sha2 + " refs/heads/" + strings.Repeat("y", 1000) + "\n")
	endless := io.MultiReader(strings.NewReader(pkt(sha1+" "+sha2+" refs/heads/x\x00\n")), &repeat{s: long})
	if _, err := ParseCommands(endless); !errors.Is(err, ErrMalformed) {
		t.Errorf("an endless command list: %v", err)
	}
}

type repeat struct {
	s   string
	off int
}

func (r *repeat) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		c := copy(p[n:], r.s[r.off:])
		n += c
		r.off = (r.off + c) % len(r.s)
	}
	return n, nil
}

func FuzzParseCommands(f *testing.F) {
	f.Add([]byte(pkt(sha1+" "+sha2+" refs/heads/x\x00report-status") + "0000PACK"))
	f.Add([]byte(pkt("shallow "+sha1) + pkt(zeros+" "+sha2+" refs/tags/v1\x00") + "0000"))
	f.Add([]byte("0000"))
	f.Fuzz(func(t *testing.T, body []byte) {
		r := bytes.NewReader(body)
		c, err := ParseCommands(r)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("error not ErrMalformed: %v", err)
			}
			return
		}
		rest, _ := io.ReadAll(r)
		if !bytes.Equal(append(append([]byte{}, c.Raw...), rest...), body) {
			t.Fatal("raw prefix + rest != body")
		}
		for _, u := range c.Refs {
			if !validRefName(u.Name) || !isSHA(u.Old) || !isSHA(u.New) {
				t.Fatalf("invalid ref accepted: %+v", u)
			}
		}
	})
}
