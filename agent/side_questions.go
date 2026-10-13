package agent

import (
	"context"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/askernel"
	"github.com/Autumn-27/artex/compaction"
	"github.com/Autumn-27/artex/sidequestion"
)

// attachSideCapture wires the side-question checkpoint capture into a run: it
// wraps the run's model with the sidequestion capture decorator (a no-op unless
// the caller installed a Publisher on ctx), so every main-loop model call is
// snapshotted for 旁路提问. Callers must invoke it AFTER opts.Model is set and
// BEFORE askernel.NewSession.
//
// The decorator stack is deliberate: only MAIN-LOOP calls pass through the
// capture decorator. Auxiliary completions — the compaction summarizer — must
// not replace the main-loop checkpoint, so when the decorator actually wrapped
// the model we build Options.CompactionSummarizer from the model BELOW it.
func attachSideCapture(ctx context.Context, opts *askernel.Options) context.Context {
	ri := RunInfoFrom(ctx)
	p := sidequestion.Parent{TaskID: ri.TaskID, ExplorationID: ri.ExplorationID, IntentID: ri.IntentID}
	if strings.HasPrefix(ri.SessionID, "conv-") {
		p.ConversationID, _ = strconv.ParseInt(strings.TrimPrefix(ri.SessionID, "conv-"), 10, 64)
	}
	if p.ConversationID == 0 && (p.TaskID == 0 || p.ExplorationID == 0) {
		return ctx
	}
	inner := opts.Model
	var wrapped bool
	ctx, opts.Model, wrapped = sidequestion.Attach(ctx, p, inner)
	if wrapped && opts.Compaction != nil && opts.CompactionSummarizer == nil {
		// 内置压缩的摘要调用绕过 checkpoint 捕获(辅助补全不抢主循环快照)。
		opts.CompactionSummarizer = compaction.NewModelSummarizer(inner, opts.MaxTokens, opts.NonStreaming)
	}
	return ctx
}
