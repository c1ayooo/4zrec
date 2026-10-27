package gates

import (
	"context"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// ScopeFunc adapts a function to core.ScopeChecker.
type ScopeFunc func(ctx context.Context, target core.Target) error

func (f ScopeFunc) Check(ctx context.Context, target core.Target) error {
	return f(ctx, target)
}

// AllowAllScope is an explicit test/dev opt-in. Never use it in production.
func AllowAllScope() core.ScopeChecker {
	return ScopeFunc(func(context.Context, core.Target) error { return nil })
}

// DenyAllScope fails closed.
func DenyAllScope() core.ScopeChecker {
	return ScopeFunc(func(context.Context, core.Target) error {
		return core.ScopeDenied("scope is not configured")
	})
}

// StaticScope allows exact hosts and their subdomains. IP/CIDR targets must
// match exactly. It is intentionally simple; real hosts should use their
// project-scope implementation.
func StaticScope(hosts ...string) core.ScopeChecker {
	allowed := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			allowed = append(allowed, h)
		}
	}
	return ScopeFunc(func(_ context.Context, target core.Target) error {
		key := target.Key()
		for _, h := range allowed {
			if key == h || strings.HasSuffix(key, "."+h) {
				return nil
			}
		}
		return core.ScopeDenied("target " + key + " is outside the authorized scope")
	})
}
