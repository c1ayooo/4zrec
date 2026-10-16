package acllm

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// retryModel wraps a chat model with norma's two retry layers:
//
//   - transport/model failures (bounded by MaxRetries, waited off with
//     RetryInterval or the exponential ladder): a failed call is re-attempted,
//     classified like norma's doStream — context cancellation NEVER retried,
//     HTTP statuses retried only on the 408/429/5xx transient set, everything
//     else (raw transport errors) retried.
//   - empty completions (bounded by EmptyResponseRetries, EmptyResponseInterval):
//     a Generate that returns an assistant message with no content, no tool
//     calls and no reasoning is re-requested.
//
// Stream retries only the call-establishment phase (the Stream() invocation
// itself failing); once a reader has been handed out, a mid-stream drop is the
// caller's to surface — retrying it could duplicate partially-streamed output.
type retryModel struct {
	next      model.ToolCallingChatModel
	retries   int // effective transport retry count
	retryWait func(attempt int) time.Duration
	empties   int // effective empty-response retry count
	emptyWait func(attempt int) time.Duration
}

func newRetryModel(next model.ToolCallingChatModel, cfg Config) *retryModel {
	return &retryModel{
		next:      next,
		retries:   effectiveRetries(cfg.MaxRetries),
		retryWait: effectiveRetryWait(cfg.RetryInterval),
		empties:   effectiveEmptyRetries(cfg.EmptyResponseRetries),
		emptyWait: effectiveRetryWait(cfg.EmptyResponseInterval),
	}
}

// WithTools re-wraps the derived model so the retry layers survive tool binding.
func (r *retryModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	inner, err := r.next.WithTools(tools)
	if err != nil {
		return nil, err
	}
	c := *r
	c.next = inner
	return &c, nil
}

func (r *retryModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	var (
		tAttempt int // transport retry attempts
		eAttempt int // empty-response retry attempts
	)
	for {
		msg, err := r.next.Generate(ctx, input, opts...)
		if err == nil {
			if eAttempt >= r.empties || !isEmptyAssistant(msg) {
				return msg, nil
			}
			eAttempt++
			if !backoffSleep(ctx, r.emptyWait(eAttempt-1)) {
				return nil, ctx.Err() // context cancelled during backoff
			}
			continue
		}
		if !retryableCallErr(ctx, err) || tAttempt >= r.retries {
			return nil, err
		}
		tAttempt++
		if !backoffSleep(ctx, r.retryWait(tAttempt-1)) {
			return nil, ctx.Err() // context cancelled during backoff
		}
	}
}

func (r *retryModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	for attempt := 0; ; attempt++ {
		sr, err := r.next.Stream(ctx, input, opts...)
		if err == nil {
			return sr, nil
		}
		if !retryableCallErr(ctx, err) || attempt >= r.retries {
			return nil, err
		}
		if !backoffSleep(ctx, r.retryWait(attempt)) {
			return nil, ctx.Err() // context cancelled during backoff
		}
	}
}

// isEmptyAssistant reports whether a completed Generate produced nothing an
// assistant turn could be built from (norma's empty-response retry condition).
func isEmptyAssistant(msg *schema.Message) bool {
	return msg == nil || (msg.Content == "" && len(msg.ToolCalls) == 0 && msg.ReasoningContent == "")
}

// retryableCallErr classifies a model-call failure the way norma's doStream
// did: cancellation (explicit, deadline, or the context already done) is never
// retried; a [StatusError] is retried only for the transient status set; any
// other error is a transport-level failure and retried — UNLESS it embeds an
// HTTP status (adapter errors do: eino-ext openai surfaces *openai.APIError,
// eino-ext claude surfaces the anthropic SDK's error), in which case the status
// decides. That last rule is load-bearing for 4zrec's quota routing: the
// transport rewrites a quota-exhausted 429 to 402 precisely so the call fails
// over immediately, and a 402 must therefore never be retried.
func retryableCallErr(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var se *StatusError
	if errors.As(err, &se) {
		return isRetryableStatus(se.StatusCode)
	}
	if code, ok := adapterErrStatus(err); ok {
		return isRetryableStatus(code)
	}
	return true
}

// adapterErrStatus extracts an HTTP status from an adapter error's text when it
// carries no structured status. Known shapes (unit-tested in agent's quota
// contract tests):
//
//   - go-openai (eino-ext openai): "error, status code: 402, status: 402 …"
//   - anthropic-sdk-go (eino-ext claude): `POST "https://…":402 Payment Required …`
//
// Only the retry decision consumes the result: a missed match costs a
// pointless retry, a false match can only suppress one — never an incorrect
// user-visible classification.
var adapterErrStatusRe = regexp.MustCompile(`(?:status(?:\s+code)?|"|HTTP)\s*:\s*([1-5]\d{2})\b`)

func adapterErrStatus(err error) (int, bool) {
	m := adapterErrStatusRe.FindStringSubmatch(err.Error())
	if len(m) < 2 {
		return 0, false
	}
	code, err2 := strconv.Atoi(m[1])
	if err2 != nil {
		return 0, false
	}
	return code, true
}

func isRetryableStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, // 408
		http.StatusTooManyRequests,     // 429
		http.StatusInternalServerError, // 500
		http.StatusBadGateway,          // 502
		http.StatusServiceUnavailable,  // 503
		http.StatusGatewayTimeout:      // 504
		return true
	}
	return false
}

// effectiveRetries: 0 → default 3; negative → disabled.
func effectiveRetries(n int) int {
	if n == 0 {
		return 3
	}
	if n < 0 {
		return 0
	}
	return n
}

// effectiveEmptyRetries: 0 → default 2; negative → disabled.
func effectiveEmptyRetries(n int) int {
	if n == 0 {
		return 2
	}
	if n < 0 {
		return 0
	}
	return n
}

// effectiveRetryWait is the wait before retry number attempt (0-based): the
// configured fixed interval when set, the exponential ladder otherwise.
func effectiveRetryWait(fixed time.Duration) func(attempt int) time.Duration {
	if fixed > 0 {
		return func(int) time.Duration { return fixed }
	}
	return expBackoff
}

// expBackoff is the default retry ladder: 0.5s, 1s, 2s, … capped at 8s.
func expBackoff(attempt int) time.Duration {
	d := 500 * time.Millisecond * (1 << attempt)
	if d > 8*time.Second {
		d = 8 * time.Second
	}
	return d
}

// backoffSleep waits d, interruptible by ctx. Returns false if the context was
// cancelled (or d is non-positive, which never happens for a real wait).
func backoffSleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
