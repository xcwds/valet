package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/xcwds/valet/internal/secrets"
)

// SecretGetter reads a notifier's token from the secret store.
type SecretGetter interface {
	Get(ctx context.Context, name string) (secrets.Secret, error)
}

func client() *http.Client {
	return &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("%q is not an http(s) URL", raw)
	}
	if u.User != nil {
		return fmt.Errorf("%q carries credentials; use token_secret", raw)
	}
	return nil
}

// Ntfy publishes to an ntfy topic URL (https://ntfy.sh/<topic> or a
// self-hosted server).
type Ntfy struct {
	URL         string
	TokenSecret string // optional secret store name of an access token
	secrets     SecretGetter
	http        *http.Client
}

// NewNtfy returns an ntfy notifier.
func NewNtfy(topicURL, tokenSecret string, s SecretGetter) (*Ntfy, error) {
	if err := checkURL(topicURL); err != nil {
		return nil, fmt.Errorf("alerts.ntfy.url: %w", err)
	}
	return &Ntfy{URL: topicURL, TokenSecret: tokenSecret, secrets: s, http: client()}, nil
}

// Name implements Notifier.
func (*Ntfy) Name() string { return "ntfy" }

// Notify implements Notifier.
func (n *Ntfy) Notify(ctx context.Context, a Alert) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, strings.NewReader(a.Body()))
	if err != nil {
		return err
	}
	req.Header.Set("Title", a.Title())
	req.Header.Set("Tags", "warning")
	priority := "default"
	if a.RuleAlert {
		priority = "high"
	}
	req.Header.Set("Priority", priority)
	if a.Link != "" {
		req.Header.Set("Click", headerSafe(a.Link, 2048))
	}
	if n.TokenSecret != "" {
		tok, err := n.secrets.Get(ctx, n.TokenSecret)
		if err != nil {
			return fmt.Errorf("ntfy token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+string(tok.Reveal()))
	}
	return do(n.http, req)
}

// Webhook POSTs the alert as JSON to any URL.
type Webhook struct {
	URL         string
	TokenSecret string
	secrets     SecretGetter
	http        *http.Client
}

// NewWebhook returns a webhook notifier.
func NewWebhook(rawURL, tokenSecret string, s SecretGetter) (*Webhook, error) {
	if err := checkURL(rawURL); err != nil {
		return nil, fmt.Errorf("alerts.webhook.url: %w", err)
	}
	return &Webhook{URL: rawURL, TokenSecret: tokenSecret, secrets: s, http: client()}, nil
}

// Name implements Notifier.
func (*Webhook) Name() string { return "webhook" }

// Notify implements Notifier.
func (w *Webhook) Notify(ctx context.Context, a Alert) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.TokenSecret != "" {
		tok, err := w.secrets.Get(ctx, w.TokenSecret)
		if err != nil {
			return fmt.Errorf("webhook token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+string(tok.Reveal()))
	}
	return do(w.http, req)
}

func do(c *http.Client, req *http.Request) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
