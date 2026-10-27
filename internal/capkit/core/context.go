package core

import "context"

type callContextKey struct{}

// WithCallContext attaches the caller/task context to a request context. The
// runtime does this before invoking a capability; gate-aware adapters read it
// for scope/audit decisions.
func WithCallContext(ctx context.Context, cc CallContext) context.Context {
	return context.WithValue(ctx, callContextKey{}, cc)
}

// CallContextFrom returns the attached call context.
func CallContextFrom(ctx context.Context) (CallContext, bool) {
	cc, ok := ctx.Value(callContextKey{}).(CallContext)
	return cc, ok
}

// ProjectIDFrom returns the project id, or 0 if unset.
func ProjectIDFrom(ctx context.Context) int64 {
	cc, _ := CallContextFrom(ctx)
	return cc.ProjectID
}
