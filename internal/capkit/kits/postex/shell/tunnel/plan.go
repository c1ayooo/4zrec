package tunnel

import (
	"context"

	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/session"
)

// Plan describes a WebShell-over-HTTP SOCKS tunnel. The host must deploy the
// page with its session executor and run the local SOCKS listener.
type Plan struct {
	Session    session.Session
	PagePath   string
	ListenHost string
	ListenPort int
}

type Status struct {
	Running   bool
	LocalAddr string
	PageURL   string
	Sessions  int
	Message   string
}

// PageDeployer is the host boundary for writing/removing the target-side page.
type PageDeployer interface {
	DeployPage(ctx context.Context, sess session.Session, path string, content []byte) error
	RemovePage(ctx context.Context, sess session.Session, path string) error
}

// Sink is the host boundary for the local SOCKS5 engine. This module ships no
// default networking implementation.
type Sink interface {
	Start(ctx context.Context, plan Plan) (*Status, error)
	Stop(ctx context.Context, sess session.Session) error
}
