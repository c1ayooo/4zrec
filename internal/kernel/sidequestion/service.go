package sidequestion

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/c1ayooo/4zrec/internal/platform/llm/acllm"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// SideQuestionService has no harness, tool executor, transcript writer or model
// failover chain. Answer is one completion; Respond adds bounded preparation
// and at most one context-overflow recovery around that completion.
type SideQuestionService struct{ Provider model.ToolCallingChatModel }

type Answer struct {
	Text    string
	Usage   acllm.Usage
	ToolUse bool
}

// callOptions renders the snapshot's generation parameters as eino per-call
// options (they used to ride the norma CompletionRequest).
func callOptions(req ModelCall) []model.Option {
	var opts []model.Option
	if req.Temperature != nil {
		opts = append(opts, model.WithTemperature(float32(*req.Temperature)))
	}
	if req.MaxTokens > 0 {
		opts = append(opts, model.WithMaxTokens(req.MaxTokens))
	}
	if len(req.Stop) > 0 {
		opts = append(opts, model.WithStop(req.Stop))
	}
	return opts
}

// modelFor returns the provider bound to the request's tool definitions — the
// eino seam carries tools on the model rather than the request, so the service
// binds them per call (answers keep tool definitions for structured tool
// context; summary requests carry none).
func (s SideQuestionService) modelFor(req ModelCall) (model.ToolCallingChatModel, error) {
	if len(req.Tools) == 0 {
		return s.Provider, nil
	}
	infos := make([]*schema.ToolInfo, 0, len(req.Tools))
	for _, t := range req.Tools {
		info, err := acllm.ToolSchemaToInfo(t)
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return s.Provider.WithTools(infos)
}

// callInput projects the snapshot's call onto eino runtime messages: the
// system segments lead as system-role messages (eino carries the system prompt
// in the input array), followed by the DTO history via acllm.ToSchema.
func callInput(req ModelCall) []*schema.Message {
	input := make([]*schema.Message, 0, len(req.System)+len(req.Messages))
	for _, s := range req.System {
		input = append(input, schema.SystemMessage(s))
	}
	return append(input, acllm.ToSchema(req.Messages)...)
}

// usageOf extracts the token usage from a message's ResponseMeta.
func usageOf(msg *schema.Message) acllm.Usage {
	if msg == nil || msg.ResponseMeta == nil {
		return acllm.Usage{}
	}
	return acllm.UsageFromToken(msg.ResponseMeta.Usage)
}

// finishReasonOf returns the message's finish reason ("max_tokens"/"length"
// mark a truncated completion).
func finishReasonOf(msg *schema.Message) string {
	if msg == nil || msg.ResponseMeta == nil {
		return ""
	}
	return msg.ResponseMeta.FinishReason
}

func (s SideQuestionService) Answer(ctx context.Context, req ModelCall, streaming bool, update func(Answer)) (out Answer, err error) {
	provider, err := s.modelFor(req)
	if err != nil {
		return out, err
	}
	input := callInput(req)
	if streaming {
		var sr *schema.StreamReader[*schema.Message]
		sr, err = provider.Stream(ctx, input, callOptions(req)...)
		if err == nil {
			complete := false
			for {
				var msg *schema.Message
				msg, err = sr.Recv()
				if errors.Is(err, io.EOF) {
					err = nil
					complete = true
					break
				}
				if err != nil {
					break
				}
				out.Text += msg.Content
				if len(msg.ToolCalls) > 0 {
					out.ToolUse = true
				}
				out.Usage.Add(usageOf(msg))
				if update != nil {
					update(out)
				}
				if ctx.Err() != nil {
					err = ctx.Err()
					break
				}
			}
			sr.Close()
			if err == nil && !complete {
				err = errors.New("模型响应中断，请重新提问")
			}
		}
	} else {
		var msg *schema.Message
		msg, err = provider.Generate(ctx, input, callOptions(req)...)
		out.Usage = usageOf(msg)
		if msg != nil {
			out.Text, out.ToolUse = msg.Content, len(msg.ToolCalls) > 0
		}
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil && strings.TrimSpace(out.Text) == "" {
		if out.ToolUse {
			out.Text = "当前旁路提问不能执行工具操作，请在主会话中发出操作请求。"
		} else {
			err = errors.New("模型没有返回回答")
		}
	}
	return out, err
}
