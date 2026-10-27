package identity

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// AuthKinds is the closed set of flow kinds a host may register (docs §5.2).
// Keeping it closed lets identity_login reject a typo before the call reaches
// the host, instead of silently having no flow to run.
var AuthKinds = []string{"form", "json", "oauth", "cas", "bearer"}

// NormalizeAuthKind lowercases a kind and checks it against AuthKinds.
func NormalizeAuthKind(kind string) (string, error) {
	k := strings.ToLower(strings.TrimSpace(kind))
	if k == "" {
		return "", fmt.Errorf("kind 必填（%s）", strings.Join(AuthKinds, "|"))
	}
	for _, known := range AuthKinds {
		if k == known {
			return k, nil
		}
	}
	return "", fmt.Errorf("kind %q 不支持（可选：%s）", kind, strings.Join(AuthKinds, "|"))
}

// AuthFlowRegistry is the host-side assembly point for site logins: the host
// registers how to log into its sites, and identity_login runs the registered
// flow. Keying by kind is what makes assembly one line — registration says "this
// is how a form site logs in", and the tool resolves it by the kind the agent
// asks for.
//
// One flow per kind. A host with several sites of the same kind registers a
// single flow that dispatches on Credentials.Fields["target"], which
// identity_login fills with the requested target.
type AuthFlowRegistry struct {
	mu    sync.RWMutex
	flows map[string]core.AuthFlow
}

// NewAuthFlowRegistry builds an empty registry.
func NewAuthFlowRegistry() *AuthFlowRegistry {
	return &AuthFlowRegistry{flows: map[string]core.AuthFlow{}}
}

// Register adds one flow under its own Kind(). Registering a kind twice is an
// error rather than a silent overwrite: a host that means to replace a flow
// should say so, and a surprising replacement would send credentials to the
// wrong site.
func (r *AuthFlowRegistry) Register(flow core.AuthFlow) error {
	if flow == nil {
		return fmt.Errorf("flow 不能为空")
	}
	kind, err := NormalizeAuthKind(flow.Kind())
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.flows[kind]; dup {
		return fmt.Errorf("kind %q 已注册", kind)
	}
	r.flows[kind] = flow
	return nil
}

// RegisterSite registers a site login in one line: the kind plus the function
// that performs it. This is the seam a host assembles a site-level login
// through without declaring a type.
func (r *AuthFlowRegistry) RegisterSite(kind string, fn func(context.Context, core.Credentials) (core.Identity, error)) error {
	if fn == nil {
		return fmt.Errorf("登录函数不能为空")
	}
	return r.Register(core.AuthFlowFunc{KindName: kind, Fn: fn})
}

// RegisterFormSite registers a cookie-jar form login for one site in one line.
// The FormFlow carries its own site parameters; the host only supplies it.
func (r *AuthFlowRegistry) RegisterFormSite(flow FormFlow) error {
	if strings.TrimSpace(flow.LoginURL) == "" {
		return fmt.Errorf("LoginURL 必填")
	}
	if flow.HTTP == nil {
		return fmt.Errorf("FormFlow 需要 HTTPDoer")
	}
	cp := flow
	return r.Register(&cp)
}

// Lookup returns the flow registered for kind.
func (r *AuthFlowRegistry) Lookup(kind string) (core.AuthFlow, bool) {
	k, err := NormalizeAuthKind(kind)
	if err != nil {
		return nil, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.flows[k]
	return f, ok
}

// Kinds returns the registered kinds, sorted, for error hints and diagnostics.
func (r *AuthFlowRegistry) Kinds() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.flows))
	for k := range r.flows {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
