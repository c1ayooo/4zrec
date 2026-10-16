package noa

import (
	"context"

	"github.com/c1ayooo/4zrec/acllm"
	"github.com/c1ayooo/4zrec/askernel"
	"github.com/c1ayooo/4zrec/compaction"
	"github.com/c1ayooo/4zrec/tools"
)

// Takeover adapts a Session to the kernel's context-manager seam.
//
// It satisfies askernel.NoaTakeover and askernel.NoaView. Implementing the
// latter is what takes over request construction from acllm.MessagesForAPI —
// the same role norma's harness.ContextView implementation played against
// llm.MessagesForAPI. The kernel consults View with the FULL DTO master
// history; Project/Reassemble slice at the last compact boundary themselves,
// and the kernel's post-projection boundary strip + PairToolBlocks are no-ops
// on the result.
type Takeover struct {
	sess *Session
	// overflow tracks what a prompt-too-long error taught us.
	overflow overflowState
}

// Compile-time seam assertions: the takeover slots into askernel's Noa options
// and, via NoaView, replaces the boundary projection for every model call.
var (
	_ askernel.NoaTakeover = (*Takeover)(nil)
	_ askernel.NoaView     = (*Takeover)(nil)
)

// Session returns the underlying session, so a host can inspect state or
// archives.
func (t *Takeover) Session() *Session { return t.sess }

// ExtraTools returns the one tool noa exposes (Compress), appended by the
// kernel to the session registry.
func (t *Takeover) ExtraTools() []tools.CoreTool {
	return []tools.CoreTool{newCompressTool(t.sess)}
}

// SystemPromptSegments returns the resident prompt sections. The kernel
// appends them after the host's own segments, before the deferred-tools block.
//
// The prompt section is fully static, so it belongs in the cacheable prefix.
// norma reflected that with DynamicBoundary; here the section's staticness is
// what makes it safe to fold into the system message the kernel rebuilds.
func (t *Takeover) SystemPromptSegments() []string {
	return []string{BuildSystemPrompt(Sections{})}
}

// View builds the request's message array (askernel.NoaView).
func (t *Takeover) View(msgs []acllm.Message) []acllm.Message {
	return t.sess.View(msgs)
}

// Pre is a no-op on the history.
//
// The kernel's built-in compaction rewrites messages here; noa must not.
// Message identity is a content hash over the stored text, and a rewrite would
// change every id derived from it, invalidating every ref the model holds.
//
// Seam note: the askernel NoaView seam carries no Pre stage and no per-turn
// provider token figure, so nothing calls this today; the session then runs
// its pressure ladder on the projected estimate (resolveTokenCount's p <= 0
// path). Kept for parity with norma's harness.Compactor.Pre.
func (t *Takeover) Pre(_ context.Context, msgs []acllm.Message, lastInputTokens int) []acllm.Message {
	if lastInputTokens > 0 {
		t.sess.noteProviderTokens(lastInputTokens)
	}
	return msgs
}

// IsOverflow reports whether err is a context-overflow rejection. The kernel's
// built-in compaction already recognises every provider's phrasing, so the
// detection is borrowed rather than duplicated.
//
// Seam note: askernel's reactive recovery uses compaction.IsOverflow directly;
// this method is the norma-parity surface.
func (t *Takeover) IsOverflow(err error) bool {
	return compaction.IsOverflow(err)
}

// Reactive recovers from a prompt-too-long error.
//
// noa cannot ask the model to compress here — the model is not in the loop at
// this point. What it can do is arm the mechanical valve and VERIFY the result:
// returning true without actually shrinking the view would produce a
// 413 → retry → 413 loop, which is worse than a clean failure. So the view is
// rebuilt and measured, and false is returned if it did not shrink.
//
// Seam note: nothing in askernel calls this — the kernel wraps the model with
// its own reactive recovery and offers the takeover no hook. Kept intact (with
// the overflow valve it drives) for parity with norma's harness.Compactor and
// future seam growth.
func (t *Takeover) Reactive(ctx context.Context, msgs []acllm.Message) ([]acllm.Message, bool) {
	// Compare against the array the provider actually rejected, not the raw
	// projection. The projection is always larger than the sent view, so
	// measuring against it would show progress on every attempt and never admit
	// that arming changed nothing.
	before := t.sess.sentTokens()

	t.overflow.arm(t.sess.Config().ModelContextLimit)
	floor := t.overflow.armedFloor()
	t.sess.setEmergencyFloor(floor)

	after := estimateMessages(t.sess.View(msgs))

	shrank := before == 0 || after < before
	fits := floor == 0 || after <= floor
	if !shrank || !fits {
		// Nothing more to give. Returning true here would promise a smaller
		// request that is not smaller, and the loop would retry into the same
		// rejection indefinitely; a clean prompt-too-long is the better outcome.
		t.sess.setEmergencyFloor(0)
		t.overflow.disarm()
		return msgs, false
	}
	return msgs, true
}

// estimateMessages sizes a rebuilt request.
func estimateMessages(msgs []acllm.Message) int {
	total := 0
	for _, m := range msgs {
		for _, b := range m.Content {
			total += len(b.Text) / 4
			total += len(b.Thinking) / 4
			total += len(b.Input) / 4
			for _, inner := range b.Content {
				total += len(inner.Text) / 4
			}
		}
	}
	return total
}
