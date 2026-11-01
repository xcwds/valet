package github

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/xcwds/valet/internal/connector"
	"github.com/xcwds/valet/internal/secrets"
)

func TestGitRemote(t *testing.T) {
	c, err := New(Config{AppID: "1", InstallationID: 2, PrivateKeySecret: "k"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]string{"XCWDS/Site": "xcwds/site", "xcwds/valet": "xcwds/valet", "a-b/c.d_e": "a-b/c.d_e"} {
		if got, err := c.GitRepo(raw); err != nil || got != want {
			t.Errorf("GitRepo(%q) = %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"", "xcwds", "xcwds/site/extra", "../x", "xcwds/..", "-x/y", "x/y z", "xcwds/site.git", "x/%2e%2e"} {
		if got, err := c.GitRepo(raw); err == nil {
			t.Errorf("GitRepo(%q) accepted as %q", raw, got)
		}
	}
	u, err := c.GitURL("xcwds/site")
	if err != nil || u.String() != "https://github.com/xcwds/site.git" {
		t.Errorf("GitURL = %v, %v", u, err)
	}
	r, _ := http.NewRequest("GET", u.String(), nil)
	c.GitAuth(r, connector.Credential{Secret: secrets.NewSecret([]byte("ghs_abc")), ExpiresAt: time.Now().Add(time.Hour)})
	if user, pass, ok := r.BasicAuth(); !ok || user != "x-access-token" || pass != "ghs_abc" {
		t.Errorf("auth = %q %q %v", user, pass, ok)
	}
}

func TestGitURLConfig(t *testing.T) {
	ok := map[string]string{
		"https://ghe.example.com/":  "https://ghe.example.com/xcwds/site.git",
		"http://127.0.0.1:9999":     "http://127.0.0.1:9999/xcwds/site.git",
		"https://ghe.example.com/x": "https://ghe.example.com/x/xcwds/site.git",
	}
	for in, want := range ok {
		c, err := New(Config{AppID: "1", InstallationID: 2, PrivateKeySecret: "k", GitURL: in}, nil)
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if u, _ := c.GitURL("xcwds/site"); u.String() != want {
			t.Errorf("%s: %s, want %s", in, u, want)
		}
	}
	for _, bad := range []string{"http://ghe.example.com", "ftp://x", "https://user:pw@ghe.example.com", "https://ghe.example.com?x=1", "github.com"} {
		if _, err := New(Config{AppID: "1", InstallationID: 2, PrivateKeySecret: "k", GitURL: bad}, nil); err == nil || !strings.Contains(err.Error(), "git_url") {
			t.Errorf("%s accepted: %v", bad, err)
		}
	}
}
