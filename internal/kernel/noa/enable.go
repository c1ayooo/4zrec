package noa

import (
	"github.com/c1ayooo/4zrec/internal/kernel/askernel"
	"github.com/c1ayooo/4zrec/internal/toolface/tools"
)

// Enable wires noa into a set of askernel Options.
//
// This is the ONLY entry point, and it is all-or-nothing by design. It attaches
// three things at once, exactly like norma noaadapter.Enable did:
//
//  1. opts.Noa.Takeover         — takes over the view (and disables the
//     kernel's built-in Compaction, which a session cannot run alongside it)
//  2. Takeover.ExtraTools       — the compression tool (Compress)
//  3. Takeover.SystemPromptSegments — the three resident prompt sections
//
// They must live or die together. Wiring them separately makes three ways to
// get it half-right, and each failure is quiet:
//
//   - no View: the model compresses, the panel says it worked, and the
//     view never changes — the compression went nowhere.
//   - no tool: the prompt teaches a tool that does not exist.
//   - no prompt: the model has the tool but not the rules, and writes summaries
//     that drop paths, decisions and error strings. Nothing reports an error;
//     it surfaces hours later as a model that has forgotten what it did.
//
// Not calling Enable is the off switch: nothing is attached, and the kernel's
// built-in compaction keeps working exactly as before. norma additionally
// carved the static prompt section out of the cache-dynamic suffix via
// DynamicBoundary; askernel rebuilds the system message from segments, so the
// static section lands in the cacheable prefix by construction.
func Enable(opts *askernel.Options, o Options) error {
	if _, err := EnableWithSession(opts, o); err != nil {
		return err
	}
	return nil
}

// EnableWithSession is Enable, also returning the session so a host can inspect
// state or archives. The session is owned by the returned wiring; callers must
// not construct a second one over the same directory.
func EnableWithSession(opts *askernel.Options, o Options) (*Session, error) {
	if o.ModelContextLimit == 0 && o.Config == nil {
		o.ModelContextLimit = defaultContextLimit
	}
	if o.OnWarn == nil {
		o.OnWarn = opts.OnWarn
	}
	t, err := NewTakeover(o)
	if err != nil {
		return nil, err
	}
	opts.Noa = &askernel.NoaOptions{
		ArchiveBaseDir:    o.ArchiveBaseDir,
		SessionID:         o.SessionID,
		Config:            o.Config,
		ModelContextLimit: o.ModelContextLimit,
		ParentSessionIDs:  o.ParentSessionIDs,
		OnWarn:            o.OnWarn,
		Now:               o.Now,
		Takeover:          t,
	}
	return t.sess, nil
}

// NewTakeover builds the noa takeover over one session, without touching any
// Options value. It is what Enable installs under askernel.Options.Noa: the
// returned value satisfies askernel.NoaTakeover and — because noa's compression
// view must replace acllm.MessagesForAPI as the request projection, exactly as
// norma's ContextView takeover replaced llm.MessagesForAPI — askernel.NoaView.
func NewTakeover(o Options) (*Takeover, error) {
	sess, err := newSession(o)
	if err != nil {
		return nil, err
	}
	return &Takeover{sess: sess}, nil
}

// defaultContextLimit is used when the host names no window. It is deliberately
// conservative: guessing high would delay every pressure threshold past the
// point where they could still help.
const defaultContextLimit = 200000

var _ tools.CoreTool = newCompressTool(&Session{cfg: DefaultConfig(1)})
