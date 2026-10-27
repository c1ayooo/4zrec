// Package shellkit exposes the WebShell/C2 foothold as capkit session tools.
// It owns no transport itself: the host injects a session.Executor for
// WebShells and a core.SessionManager, and these tools drive them through the
// same contract SSH and WinRM use.
package shell

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/postex/shell/session"
)

// WebShellOpener adapts a host session.Executor into a core.SessionOpener
// for kind "webshell". Shell parameters (cmd param, password, protocol) travel
// in SessionSpec.Options so the tool input stays transport-neutral.
type WebShellOpener struct {
	Executor session.Executor
}

// Open builds a WebShell-backed core.Session.
func (o *WebShellOpener) Open(_ context.Context, spec core.SessionSpec) (core.Session, error) {
	if o.Executor == nil {
		return nil, fmt.Errorf("WebShell Executor 未注入（宿主需提供 shellkit/session.Executor）")
	}
	shell := session.Session{
		URL:          spec.Host,
		ShellType:    opt(spec, "shell_type"),
		Method:       opt(spec, "method"),
		CmdParam:     opt(spec, "cmd_param"),
		PassParam:    opt(spec, "pass_param"),
		Protocol:     firstOpt(spec, "protocol", spec.Protocol),
		ParamChannel: opt(spec, "param_channel"),
		Encoding:     opt(spec, "encoding"),
		ProxyURL:     firstOpt(spec, "proxy", spec.ProxyURL),
		Password:     spec.Secret,
	}
	if idStr := opt(spec, "id"); idStr != "" {
		if id, err := strconv.ParseInt(idStr, 10, 64); err == nil {
			shell.ID = id
		}
	}
	return &session.CapabilitySession{Shell: shell, Executor: o.Executor}, nil
}

func opt(spec core.SessionSpec, key string) string {
	if spec.Options == nil {
		return ""
	}
	return strings.TrimSpace(spec.Options[key])
}

func firstOpt(spec core.SessionSpec, key, fallback string) string {
	if v := opt(spec, key); v != "" {
		return v
	}
	return strings.TrimSpace(fallback)
}
