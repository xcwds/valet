package github

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/xcwds/valet/internal/connector"
)

var gitRepoRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}/[a-z0-9_-][a-z0-9._-]{0,99}$`)

// GitRepo implements connector.GitRemote: GitHub names are
// case-insensitive, so the canonical form is lowercase, the same form the
// actions' repo params require (#13).
func (c *Connector) GitRepo(raw string) (string, error) {
	repo := strings.ToLower(raw)
	if !gitRepoRe.MatchString(repo) || strings.HasSuffix(repo, ".git") {
		return "", fmt.Errorf("github: invalid repository %q", raw)
	}
	return repo, nil
}

// GitURL implements connector.GitRemote.
func (c *Connector) GitURL(repo string) (*url.URL, error) {
	if !gitRepoRe.MatchString(repo) {
		return nil, fmt.Errorf("github: invalid repository %q", repo)
	}
	return url.Parse(c.cfg.GitURL + "/" + repo + ".git")
}

// GitAuth implements connector.GitRemote: an installation token is sent as
// the password for the user x-access-token.
func (c *Connector) GitAuth(r *http.Request, cred connector.Credential) {
	r.SetBasicAuth("x-access-token", string(cred.Secret.Reveal()))
}

var _ connector.GitRemote = (*Connector)(nil)
