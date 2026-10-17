package acllm

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	eclaude "github.com/cloudwego/eino-ext/components/model/claude"
	eopenai "github.com/cloudwego/eino-ext/components/model/openai"
	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"
)

// NewChatModel turns a persisted provider Config into a cloudwego/eino chat
// model for its wire format:
//
//   - FormatOpenAI           → eino-ext openai (Chat Completions)
//   - FormatAnthropic        → eino-ext claude (Messages API)
//   - FormatOpenAIResponses  → the self-built responses provider in responses.go
//
// The returned model is decorated, outermost first: rate limit (one token
// bucket per built model, retries excluded) → retry (transport + empty-response
// layers) → per-call defaults (Config.Temperature/Stop/MaxTokens injected as
// default options; a caller's explicit model.Option wins). WithTools flows
// through every decorator unchanged.
func NewChatModel(ctx context.Context, cfg Config) (model.ToolCallingChatModel, error) {
	client, err := resolveHTTPClient(cfg)
	if err != nil {
		return nil, err
	}
	if client != nil {
		cfg.HTTPClient = client
	}

	var base model.ToolCallingChatModel
	switch cfg.Format {
	case FormatAnthropic:
		base, err = newAnthropicChatModel(ctx, cfg)
	case FormatOpenAI:
		base, err = newOpenAIChatModel(ctx, cfg)
	case FormatOpenAIResponses:
		base = newResponsesModel(cfg)
	default:
		return nil, fmt.Errorf("acllm: unknown format %q (use anthropic, openai or openai-responses)", cfg.Format)
	}
	if err != nil {
		return nil, err
	}

	m := withCallDefaults(base, callDefaultOptions(cfg, cfg.Format == FormatAnthropic))
	m = newRetryModel(m, cfg)
	if rl := newRateLimiter(cfg.RateLimit); rl != nil {
		m = &rateLimitedModel{next: m, l: rl}
	}
	return m, nil
}

// resolveHTTPClient builds the outbound client from cfg.Proxy when no client
// was supplied (norma provider.go behavior). Both empty → nil, nil: the
// eino-ext providers keep their own default client.
func resolveHTTPClient(cfg Config) (*http.Client, error) {
	if cfg.HTTPClient != nil || cfg.Proxy == "" {
		return nil, nil
	}
	u, err := url.Parse(cfg.Proxy)
	if err != nil {
		return nil, fmt.Errorf("acllm: invalid proxy %q: %w", cfg.Proxy, err)
	}
	switch u.Scheme {
	case "http", "https", "socks5": // supported by net/http's Transport.Proxy
	case "":
		return nil, fmt.Errorf("acllm: proxy %q missing scheme (use http://, https:// or socks5://)", cfg.Proxy)
	default:
		return nil, fmt.Errorf("acllm: unsupported proxy scheme %q (use http, https or socks5)", u.Scheme)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyURL(u)
	return &http.Client{Transport: tr}, nil
}

// newOpenAIChatModel maps Config onto the eino-ext openai Chat Completions
// adapter. Temperature/Stop/MaxTokens are NOT config-level (norma applied them
// per request): they ride the call-defaults decorator, except the
// max_completion_tokens variant which only exists as a config field in the
// adapter and is therefore set there.
func newOpenAIChatModel(ctx context.Context, cfg Config) (model.ToolCallingChatModel, error) {
	mc := &eopenai.ChatModelConfig{
		APIKey:          cfg.APIKey,
		BaseURL:         cfg.BaseURL,
		Model:           cfg.Model,
		APIVersion:      cfg.APIVersion,
		HTTPClient:      cfg.HTTPClient,
		ReasoningEffort: eopenai.ReasoningEffortLevel(cfg.ReasoningEffort), // "" → zero value, not sent
	}
	if cfg.MaxTokens > 0 && cfg.MaxTokensField == MaxTokensFieldCompletion {
		mt := cfg.MaxTokens
		mc.MaxCompletionTokens = &mt
	}
	return eopenai.NewChatModel(ctx, mc)
}

// newAnthropicChatModel maps Config onto the eino-ext claude adapter. The
// adapter has no APIVersion/output_config field: the SDK's default
// anthropic-version header applies and ReasoningEffort (norma's
// output_config.effort) has no equivalent and is ignored.
func newAnthropicChatModel(ctx context.Context, cfg Config) (model.ToolCallingChatModel, error) {
	cc := &eclaude.Config{
		APIKey:     cfg.APIKey,
		Model:      cfg.Model,
		HTTPClient: cfg.HTTPClient,
		Thinking:   claudeThinking(cfg),
	}
	if cfg.BaseURL != "" {
		b := cfg.BaseURL
		cc.BaseURL = &b
	}
	return eclaude.NewChatModel(ctx, cc)
}

// claudeThinking replicates norma's Anthropic thinking derivation. Norma sent
// the switch verbatim as "thinking":{"type":cfg.ThinkingType} (omitted when
// ""), with no budget_tokens — the endpoint supplied the budget, and norma
// defaulted the Messages API max_tokens to 8192 when unset. The eino-ext
// adapter needs an explicit Enable/BudgetTokens pair, so the budget is derived
// from the effective max_tokens: half of it, floored at the API minimum 1024.
//
//	""            → nil (omit; adapter/provider default = thinking off)
//	"disabled"    → {Enable:false} (adapter omits the parameter — same wire effect)
//	"enabled"     → {Enable:true, BudgetTokens:max(1024, maxTokens/2)}, maxTokens = cfg.MaxTokens or norma's 8192 default
//	anything else → nil (the adapter can only express on/off)
func claudeThinking(cfg Config) *eclaude.Thinking {
	switch cfg.ThinkingType {
	case "disabled":
		return &eclaude.Thinking{Enable: false}
	case "enabled":
		maxTok := cfg.MaxTokens
		if maxTok <= 0 {
			maxTok = 8192 // norma's Anthropic max_tokens default
		}
		budget := maxTok / 2
		if budget < 1024 {
			budget = 1024 // Anthropic API minimum
		}
		return &eclaude.Thinking{Enable: true, BudgetTokens: budget}
	default:
		return nil
	}
}

// callDefaultOptions renders Config.Temperature/Stop/MaxTokens as per-call
// default options (norma applied these per request, not per provider). For
// openai with MaxTokensField=max_completion_tokens the cap is config-level
// instead, so no WithMaxTokens default is injected (sending both keys is not
// norma's "exactly one key" contract). anthropic reports whether the
// anthropic 8192 default applies.
func callDefaultOptions(cfg Config, anthropic bool) []model.Option {
	var opts []model.Option
	if cfg.Temperature != nil {
		t := float32(*cfg.Temperature)
		opts = append(opts, model.WithTemperature(t))
	}
	if len(cfg.Stop) > 0 {
		opts = append(opts, model.WithStop(cfg.Stop))
	}
	maxTok := cfg.MaxTokens
	if anthropic && maxTok <= 0 {
		maxTok = 8192 // the Messages API requires the field; norma's default
	}
	if maxTok > 0 && !(cfg.Format == FormatOpenAI && cfg.MaxTokensField == MaxTokensFieldCompletion) {
		opts = append(opts, model.WithMaxTokens(maxTok))
	}
	return opts
}

// callDefaultsModel injects the Config-derived default options ahead of every
// call's options. GetCommonOptions applies options in order, so the caller's
// own model.With* choices (applied later) win over these defaults.
type callDefaultsModel struct {
	next     model.ToolCallingChatModel
	defaults []model.Option
}

func withCallDefaults(next model.ToolCallingChatModel, defaults []model.Option) model.ToolCallingChatModel {
	if len(defaults) == 0 {
		return next
	}
	return &callDefaultsModel{next: next, defaults: defaults}
}

func (m *callDefaultsModel) options(opts []model.Option) []model.Option {
	out := make([]model.Option, 0, len(m.defaults)+len(opts))
	out = append(out, m.defaults...)
	return append(out, opts...)
}

func (m *callDefaultsModel) WithTools(tools []*schema.ToolInfo) (model.ToolCallingChatModel, error) {
	inner, err := m.next.WithTools(tools)
	if err != nil {
		return nil, err
	}
	return &callDefaultsModel{next: inner, defaults: m.defaults}, nil
}

func (m *callDefaultsModel) Generate(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.Message, error) {
	return m.next.Generate(ctx, input, m.options(opts)...)
}

func (m *callDefaultsModel) Stream(ctx context.Context, input []*schema.Message, opts ...model.Option) (*schema.StreamReader[*schema.Message], error) {
	return m.next.Stream(ctx, input, m.options(opts)...)
}

// StatusError is a non-2xx HTTP response from a provider. The retry decorator
// classifies it with norma's transient-status set; other errors are treated as
// transport failures.
type StatusError struct {
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("acllm: status %d: %s", e.StatusCode, truncateBody(e.Body, 500))
}

func truncateBody(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
