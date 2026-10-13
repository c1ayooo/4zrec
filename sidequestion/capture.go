// Package sidequestion captures immutable main-agent checkpoints. It never owns
// an agent session or a tool executor.
package sidequestion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/acllm"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

type Parent struct {
	ConversationID int64 `json:"conversation_id,omitempty"`
	TaskID         int64 `json:"task_id,omitempty"`
	ExplorationID  int64 `json:"exploration_id,omitempty"`
	IntentID       int64 `json:"intent_id,omitempty"`
}

func (p Parent) Key() string {
	if p.ConversationID > 0 {
		return fmt.Sprintf("conv-%d", p.ConversationID)
	}
	if p.IntentID > 0 {
		return fmt.Sprintf("task-%d-exp-%d-worker-i%d", p.TaskID, p.ExplorationID, p.IntentID)
	}
	return fmt.Sprintf("task-%d-exp-%d-main", p.TaskID, p.ExplorationID)
}

// Model contains only configuration identity, never credentials or proxy URLs.
type Model struct {
	ProfileID    int64  `json:"profile_id"`
	Name         string `json:"name"`
	Format       string `json:"format"`
	Model        string `json:"model"`
	Identity     string `json:"identity"`
	Streaming    bool   `json:"streaming"`
	WindowTokens int    `json:"window_tokens"`
}

// ModelCall is the immutable snapshot of one main-loop model invocation: the
// eino call (input messages projected back to the acllm DTO vocabulary via
// acllm.FromSchema, plus bound tools and call options) at the moment it was
// issued. Field names deliberately match the norma-era CompletionRequest JSON
// (no tags → Go field names), so snapshots persisted before the eino migration
// still decode (the dropped per-request Thinking field is ignored).
type ModelCall struct {
	// System is the system prompt, in segments, as carried by the eino input's
	// system-role messages.
	System []string
	// Messages is the API-ready DTO history (boundary-stripped, tool blocks
	// paired) the model was about to receive.
	Messages    []acllm.Message
	Tools       []acllm.ToolSchema
	MaxTokens   int
	Temperature *float64
	Stop        []string
}

type Snapshot struct {
	Parent     Parent    `json:"parent"`
	RunID      int64     `json:"run_id"`
	Version    int64     `json:"version"`
	CapturedAt time.Time `json:"captured_at"`
	Model      Model     `json:"model"`
	Request    ModelCall `json:"request"`
}

func CloneRequest(req ModelCall) (ModelCall, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return ModelCall{}, err
	}
	var out ModelCall
	err = json.Unmarshal(b, &out)
	return out, err
}

type Publisher func(Snapshot)
type publisherKey struct{}
type captureKey struct{}
type attemptKey struct{}

func WithPublisher(ctx context.Context, publish Publisher) context.Context {
	return context.WithValue(ctx, publisherKey{}, publish)
}

// Capture accumulates the checkpoints of one main run. The decorator returned
// by Attach owns it and marks every call it forwards with the attempt key, so
// the bound models BELOW any routing pool — which know which concrete member
// actually served the call — can attribute the snapshot to that member.
// Auxiliary completions (compaction summaries, side answers) bypass the
// decorator and lack the marker, so they never replace the checkpoint.
type Capture struct {
	mu      sync.Mutex
	parent  Parent
	runID   int64
	version int64
	publish Publisher
	last    *Snapshot
}

// Attach returns ctx plus a model decorator that marks every call made through
// it as a main-loop model attempt. Snapshots are only written when a publisher
// is installed on ctx; without one the inner model is returned unchanged.
func Attach(ctx context.Context, parent Parent, inner model.ToolCallingChatModel) (context.Context, model.ToolCallingChatModel) {
	publish, _ := ctx.Value(publisherKey{}).(Publisher)
	if publish == nil || inner == nil {
		return ctx, inner
	}
	c := &Capture{parent: parent, runID: time.Now().UnixNano(), publish: publish}
	return context.WithValue(ctx, captureKey{}, c), &captureModel{capture: c, next: inner}
}

// captureModel is the marking decorator: it injects the attempt marker into
// every call's context and otherwise forwards untouched.
type captureModel struct {
	capture *Capture
	next    model.ToolCallingChatModel
}

func (m *captureModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	inner, err := m.next.WithTools(tools)
	if err != nil {
		return nil, err
	}
	return &captureModel{capture: m.capture, next: inner}, nil
}

func (m *captureModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	return m.next.Generate(context.WithValue(ctx, attemptKey{}, m.capture), input, opts...)
}

func (m *captureModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return m.next.Stream(context.WithValue(ctx, attemptKey{}, m.capture), input, opts...)
}

func attemptCaptureFrom(ctx context.Context) *Capture {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(attemptKey{}).(*Capture)
	return c
}

// save stores one checkpoint. The request is deep-copied first so later
// mutation of the caller's slices cannot alias published state; response, when
// non-nil, is the model's completed reply, projected back to the DTO and
// appended to the recorded request.
// Observability must not break the main run: clone failures are swallowed.
func (c *Capture) save(m Model, call ModelCall, response *schema.Message) {
	stored, err := CloneRequest(call)
	if err != nil {
		return
	}
	if response != nil {
		dto := acllm.FromSchema([]*schema.Message{response})
		if len(dto) > 0 {
			stored.Messages = acllm.MessagesForAPI(append(append([]acllm.Message{}, stored.Messages...), dto...))
		}
	}
	c.mu.Lock()
	c.version++
	s := Snapshot{Parent: c.parent, RunID: c.runID, Version: c.version, CapturedAt: time.Now().UTC(), Model: m, Request: stored}
	c.last = &s
	c.mu.Unlock()
	c.publish(s)
}

// Finish adds tool results that landed after the final model request. The
// kernel's terminal keeps the DTO master history; the host reminder the kernel
// prepends to each request is not part of it and is carried over explicitly.
func Finish(ctx context.Context, messages []acllm.Message) {
	c, _ := ctx.Value(captureKey{}).(*Capture)
	if c == nil {
		return
	}
	c.mu.Lock()
	s := c.last
	c.mu.Unlock()
	if s == nil {
		return
	}
	req := s.Request
	var prefix []acllm.Message
	if len(req.Messages) > 0 && strings.HasPrefix(req.Messages[0].Text(), "<system-reminder>") {
		prefix = append(prefix, req.Messages[0])
	}
	req.Messages = append(prefix, acllm.MessagesForAPI(messages)...)
	c.save(s.Model, req, nil)
}

// boundModel binds a concrete model to a configuration identity. It belongs
// immediately around a concrete model, inside any routing pool, so the
// checkpoint records the member that actually served the call.
type boundModel struct {
	inner model.ToolCallingChatModel
	id    Model
	tools []*schema.ToolInfo // tools bound onto this model via WithTools
}

// Bind wraps inner so calls marked as main-loop attempts (see Attach) snapshot
// the exact invocation under the given configuration identity.
func Bind(inner model.ToolCallingChatModel, id Model) model.ToolCallingChatModel {
	return &boundModel{inner: inner, id: id}
}

func (p *boundModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	inner, err := p.inner.WithTools(tools)
	if err != nil {
		return nil, err
	}
	return &boundModel{inner: inner, id: p.id, tools: append(append([]*schema.ToolInfo{}, p.tools...), tools...)}, nil
}

func (p *boundModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	c := attemptCaptureFrom(ctx)
	if c == nil {
		return p.inner.Generate(ctx, input, opts...)
	}
	call := newCall(input, opts, p.tools)
	c.save(p.id, call, nil)
	msg, err := p.inner.Generate(ctx, input, opts...)
	if err == nil && msg != nil && ctx.Err() == nil {
		c.save(p.id, call, msg)
	}
	return msg, err
}

func (p *boundModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	c := attemptCaptureFrom(ctx)
	if c == nil {
		return p.inner.Stream(ctx, input, opts...)
	}
	call := newCall(input, opts, p.tools)
	c.save(p.id, call, nil)
	sr, err := p.inner.Stream(ctx, input, opts...)
	if err != nil {
		return nil, err
	}
	// eino stream readers are single-reader: pump the inner stream through an
	// UNBUFFERED pipe so the consumer receives identical chunks while the pump
	// accumulates the reply. Unbuffered is what makes an early consumer close
	// observable — the pending Send fails instead of draining into a buffer —
	// and a closed or failed stream keeps the request-start checkpoint as the
	// last valid boundary.
	out, sw := schema.Pipe[*schema.Message](0)
	go func() {
		defer sw.Close()
		defer sr.Close()
		var acc *schema.Message
		for {
			msg, rerr := sr.Recv()
			if rerr == nil && msg != nil {
				if acc == nil {
					acc = msg
				} else {
					acc, _ = schema.ConcatMessages([]*schema.Message{acc, msg})
				}
			}
			if sw.Send(msg, rerr) {
				return // consumer closed early: partial reply is not published
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) && acc != nil && ctx.Err() == nil {
					c.save(p.id, call, acc)
				}
				return
			}
		}
	}()
	return out, nil
}

// newCall snapshots the exact invocation: system segments and DTO messages from
// the eino input, tools from the bound set plus call options, and the options
// themselves.
func newCall(input []*schema.Message, opts []model.Option, bound []*schema.ToolInfo) ModelCall {
	var call ModelCall
	for _, m := range input {
		if m != nil && m.Role == schema.System {
			call.System = append(call.System, m.Content)
		}
	}
	call.Messages = acllm.MessagesForAPI(acllm.FromSchema(input))
	common := model.GetCommonOptions(&model.Options{}, opts...)
	for _, t := range append(append([]*schema.ToolInfo{}, bound...), common.Tools...) {
		call.Tools = append(call.Tools, toolSchemaOf(t))
	}
	if common.Temperature != nil {
		t := float64(*common.Temperature)
		call.Temperature = &t
	}
	if common.MaxTokens != nil {
		call.MaxTokens = *common.MaxTokens
	}
	call.Stop = common.Stop
	return call
}

// toolSchemaOf converts an eino ToolInfo into the DTO tool schema (names plus
// JSON-schema input schema) for the snapshot.
func toolSchemaOf(info *schema.ToolInfo) acllm.ToolSchema {
	ts := acllm.ToolSchema{Name: info.Name, Description: info.Desc}
	if info.ParamsOneOf != nil {
		if js, err := info.ParamsOneOf.ToJSONSchema(); err == nil && js != nil {
			if b, err := json.Marshal(js); err == nil {
				_ = json.Unmarshal(b, &ts.InputSchema)
			}
		}
	}
	return ts
}
