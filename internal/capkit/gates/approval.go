package gates

import (
	"context"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// ApproverFunc adapts a function to core.Approver.
type ApproverFunc func(ctx context.Context, req core.ApprovalRequest) error

func (f ApproverFunc) Require(ctx context.Context, req core.ApprovalRequest) error {
	return f(ctx, req)
}

// AutoApprove is an explicit test/dev opt-in. Never use it in production.
func AutoApprove() core.Approver {
	return ApproverFunc(func(context.Context, core.ApprovalRequest) error { return nil })
}

// DenyAll denies every approval request.
func DenyAll() core.Approver {
	return ApproverFunc(func(context.Context, core.ApprovalRequest) error {
		return core.NewError(core.CodeApprovalRequired, "approval is not configured")
	})
}
