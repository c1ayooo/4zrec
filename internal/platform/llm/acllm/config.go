package acllm

import (
	"net/http"
	"time"
)

// Config is the persisted model-provider configuration: exactly the norma
// llm.Config vocabulary (field names kept; JSON tags snake_case, matching the
// llm_profiles columns). One Config turns into one eino chat model via
// [NewChatModel]; MaxTokens/Temperature/Stop travel as PER-CALL defaults
// (norma applied them per request), retry/ratelimit ride as decorators.
type Config struct {
	Format     Format
	BaseURL    string `json:"base_url,omitempty"`
	APIKey     string `json:"api_key,omitempty"`
	Model      string `json:"model"`
	APIVersion string `json:"api_version,omitempty"` // Anthropic only; norma default 2023-06-01
	// HTTPClient, when set, is handed to the provider as-is. When nil, Proxy
	// below builds one; when both are empty the eino-ext default client applies.
	HTTPClient *http.Client `json:"-"`
	// Proxy, when set, routes model requests through the given proxy URL —
	// "http://", "https://" or "socks5://" (optionally user:pass@). Ignored when
	// HTTPClient is supplied. Empty leaves the provider's own default.
	Proxy string `json:"proxy,omitempty"`
	// MaxRetries bounds retries of failed calls (transport errors and
	// retryable HTTP statuses). 0 = default 3; negative disables.
	MaxRetries int `json:"max_retries,omitempty"`
	// RetryInterval, when > 0, replaces the exponential backoff between retries
	// with this FIXED wait. 0 keeps the 0.5s/1s/2s… ladder capped at 8s.
	RetryInterval time.Duration `json:"retry_interval,omitempty"`
	// EmptyResponseRetries bounds how many times a completed-but-EMPTY assistant
	// message (no content, no tool calls, no reasoning) is re-requested.
	// 0 = default 2; negative disables. Applies to Generate only.
	EmptyResponseRetries int `json:"empty_response_retries,omitempty"`
	// EmptyResponseInterval, when > 0, replaces the exponential backoff before
	// each empty-response retry. 0 keeps the ladder.
	EmptyResponseInterval time.Duration `json:"empty_response_interval,omitempty"`
	// RateLimit, when set, bounds the request rate shared across every call made
	// through the built model (per-second and/or per-minute). Retries do not
	// count against it (the limiter wraps the retry decorator).
	RateLimit *RateLimit `json:"rate_limit,omitempty"`

	// ThinkingType toggles extended/reasoning mode. "" omits the parameter
	// (provider default); "enabled"/"disabled" map to the format's thinking
	// switch (Anthropic thinking.type; eino-ext claude Thinking).
	ThinkingType string `json:"thinking_type,omitempty"`
	// ReasoningEffort sets the reasoning strength. "" omits it. OpenAI maps it
	// to "reasoning_effort"; the eino-ext claude adapter has no output_config
	// equivalent, so it is ignored for the anthropic format.
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
	// MaxTokensField selects which request key carries the output cap on
	// FormatOpenAI. "" (default) sends the classic "max_tokens";
	// MaxTokensFieldCompletion sends "max_completion_tokens" instead (required
	// by OpenAI's reasoning models). Ignored by the anthropic and responses
	// formats, which name the field themselves.
	MaxTokensField string `json:"max_tokens_field,omitempty"`

	// MaxTokens caps a single reply's output in tokens. 0 = no cap sent
	// (endpoint default), except the anthropic format where norma defaulted
	// 8192 (the Messages API requires the field).
	MaxTokens int `json:"max_tokens,omitempty"`
	// Temperature, when set, is applied as a per-call default (a caller's
	// explicit model.WithTemperature wins).
	Temperature *float64 `json:"temperature,omitempty"`
	// Stop sequences, when non-empty, are applied as per-call defaults.
	Stop []string `json:"stop,omitempty"`
}

// Format selects the wire protocol of the provider.
type Format string

const (
	FormatAnthropic Format = "anthropic"
	FormatOpenAI    Format = "openai"
	// FormatOpenAIResponses speaks the OpenAI Responses API (POST /v1/responses),
	// distinct from FormatOpenAI's Chat Completions (/chat/completions).
	FormatOpenAIResponses Format = "openai-responses"
)

// MaxTokensFieldCompletion is the Config.MaxTokensField value that moves the
// OpenAI Chat Completions output cap onto "max_completion_tokens". Any other
// value keeps the classic "max_tokens".
const MaxTokensFieldCompletion = "max_completion_tokens"

// RateLimit configures a shared request-rate limit for a model. A window with a
// zero value is unlimited. The limit is enforced across ALL calls that go
// through the one model built from a Config (one limiter per NewChatModel), so
// any number of concurrent callers sharing it are bounded by a single limit.
// Only the logical request is counted: retries inside the retry decorator do
// not consume additional tokens.
type RateLimit struct {
	PerSecond float64 // max requests per second (0 = unlimited)
	PerMinute float64 // max requests per minute (0 = unlimited)
	// Burst is the per-second bucket capacity (how many may go at once before
	// smoothing). 0 = default to PerSecond.
	Burst float64
	// OnWait, when set, is called once per acquired request with how long the
	// caller blocked on the limiter (0 if it passed immediately). Observability
	// hook; nil disables it.
	OnWait func(blocked time.Duration)
}
