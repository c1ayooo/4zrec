package noa

import "testing"

// The parser itself, over the phrasings it claims to cover. (norma's
// overflow_test.go also exercised Compactor.Pre/IsOverflow/Reactive — the
// harness-facing recovery surface. Under the askernel seam the kernel owns
// overflow recovery and offers the takeover no hook, so only the error-mining
// half is reachable and ported.)
func TestParseOverflowWindowCoversItsPatterns(t *testing.T) {
	cases := map[string]int{
		"This model's maximum context length is 200000 tokens": 200000,
		"context window of 131072 exceeded":                    131072,
		"max_tokens must be less than 8192":                    8192,
		"requests are limited to 32000 tokens":                 32000,
		"rate limit exceeded":                                  0,
		"maximum context length is zero":                       0,
	}
	for msg, want := range cases {
		if got := ParseOverflowWindow(msg); got != want {
			t.Errorf("ParseOverflowWindow(%q) = %d, want %d", msg, got, want)
		}
	}
}
