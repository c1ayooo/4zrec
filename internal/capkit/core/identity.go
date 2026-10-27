package core

import (
	"context"
	"net/http"
	"time"
)

// This file defines the target-side identity contract (see docs §5.2).
// "Identity" is who the tool acts AS against the target (cookies, bearer
// tokens, CSRF), distinct from the platform-side identity of who is allowed to
// attack. The host implements the site-specific AuthFlow; capkit supplies the
// cookie jar, CSRF extraction and token-refresh decision logic.

// Identity produces the HTTP headers that authenticate a request to a target.
type Identity interface {
	Headers(ctx context.Context) (http.Header, error)
	Refresh(ctx context.Context) error
	Scope() IdentityScope
}

// IdentityScope bounds what an identity may be used for.
type IdentityScope struct {
	ProjectID int64    `json:"project_id,omitempty"`
	Hosts     []string `json:"hosts,omitempty"`
	User      string   `json:"user,omitempty"`
	Label     string   `json:"label,omitempty"`
}

// Credentials is the cleartext credential set handed to an AuthFlow. The host
// resolves these from the Sealer at the edge; kits never persist them.
type Credentials struct {
	Username string            `json:"username,omitempty"`
	Password string            `json:"password,omitempty"`
	Token    string            `json:"token,omitempty"`
	Cookies  map[string]string `json:"cookies,omitempty"`
	Fields   map[string]string `json:"fields,omitempty"`
	Actor    string            `json:"actor,omitempty"`
}

// AuthFlow performs a site-specific login and returns an Identity. The host
// implements concrete flows (form/json/oauth/cas/bearer); capkit provides
// helpers for the common steps.
type AuthFlow interface {
	Kind() string
	Login(ctx context.Context, creds Credentials) (Identity, error)
}

// AuthFlowFunc adapts a function to AuthFlow.
type AuthFlowFunc struct {
	KindName string
	Fn       func(ctx context.Context, creds Credentials) (Identity, error)
}

func (f AuthFlowFunc) Kind() string { return f.KindName }
func (f AuthFlowFunc) Login(ctx context.Context, creds Credentials) (Identity, error) {
	return f.Fn(ctx, creds)
}

// TokenSnapshot captures a token's lifetime so the refresh decision is data,
// not guesswork.
type TokenSnapshot struct {
	AccessToken string    `json:"access_token,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	IssuedAt    time.Time `json:"issued_at,omitempty"`
}

// NeedsRefresh reports whether the token should be refreshed at now given a
// safety skew. A zero ExpiresAt is treated as "no expiry information" and never
// triggers a refresh on its own.
func (t TokenSnapshot) NeedsRefresh(now time.Time, skew time.Duration) bool {
	if t.ExpiresAt.IsZero() {
		return false
	}
	return !now.Add(skew).Before(t.ExpiresAt)
}
