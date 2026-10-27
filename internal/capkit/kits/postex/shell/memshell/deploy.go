package memshell

import (
	"context"

	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/session"
)

// DeployPlan is a pure description of a memory-shell deployment. The host must
// provide the actual file write, trigger request and cleanup.
type DeployPlan struct {
	Session    session.Session
	Payload    Payload
	DropPath   string
	TriggerURL string
	ExtraFiles map[string]string // e.g. php .user.ini
	Register   bool
}

type DeployResult struct {
	TriggerOutput  string
	TrafficID      string
	DropperRemoved bool
	ConnectionID   *int64
	Message        string
}

// Deployer is the host boundary for memory-shell deployment/removal. This
// module ships no default deployer.
type Deployer interface {
	Deploy(ctx context.Context, plan DeployPlan) (*DeployResult, error)
	Remove(ctx context.Context, plan DeployPlan) (*DeployResult, error)
}
