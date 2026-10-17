package db

import "testing"

func TestMatchLLMPricing(t *testing.T) {
	rules := []LLMPricing{
		{ModelPattern: "deepseek-v4-flash", InputPerMTok: 2, OutputPerMTok: 8, CacheReadPerMTok: 0.5},
		{ModelPattern: "deepseek-*", InputPerMTok: 3, OutputPerMTok: 9, CacheReadPerMTok: 0.6},
		{ModelPattern: "GLM-*", InputPerMTok: 4, OutputPerMTok: 16, CacheReadPerMTok: 0.8},
	}
	// 精确匹配优先于通配
	if r, ok := MatchLLMPricing(rules, "deepseek-v4-flash"); !ok || r.InputPerMTok != 2 {
		t.Fatalf("exact match failed: %+v ok=%v", r, ok)
	}
	// 通配(大小写不敏感)
	if r, ok := MatchLLMPricing(rules, "glm-5.3-flash"); !ok || r.OutputPerMTok != 16 {
		t.Fatalf("wildcard match failed: %+v ok=%v", r, ok)
	}
	// 无匹配
	if _, ok := MatchLLMPricing(rules, "claude-x"); ok {
		t.Fatal("claude-x should have no rule")
	}
	// 最长前缀优先
	rules = append(rules, LLMPricing{ModelPattern: "deepseek-v4-*", InputPerMTok: 1})
	if r, ok := MatchLLMPricing(rules, "deepseek-v4-pro"); !ok || r.InputPerMTok != 1 {
		t.Fatalf("longest prefix should win: %+v ok=%v", r, ok)
	}
}
