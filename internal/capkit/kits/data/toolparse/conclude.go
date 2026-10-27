package toolparse

import (
	"encoding/json"
	"fmt"
	"strings"
)

// conclude.go —— 强制收尾轮（run_conclude，Cairn conclude 对标）的回执解析：
// 任务命中 timeout / max_iterations 时，平台用同一 session 发一条收尾指令，模型把
// 「已识别未落库」的增量事实以 JSON 信封交回，本模块解析后交 FactStore 落库。
// 写入通道单一（模型只回 JSON，平台校验落库），不依赖模型自觉调 upsert_project_fact。

// ConcludeEnvelope 收尾轮回执信封。category 不在信封字段里——由 fact_key 前缀推导
// （键即分类的单一事实源，与 ValidCategories 白名单同口径）。
type ConcludeEnvelope struct {
	Facts    []FactCandidate `json:"facts"`
	Residual string          `json:"residual"`
}

// ConcludeMaxFacts 解析层硬顶（提示词限 12 条，此处放余量防灌库）。
const ConcludeMaxFacts = 20

// ParseConcludeOutput 从收尾轮回复文本解析增量事实信封（fail-closed）。
// 候选 JSON 依次尝试：``` 围栏块 → 顶层平衡对象 → 整段文本；候选必须含 "facts" 字段
// （防把无关 JSON/工具回显误收为信封）。全部失败返回 error，不落任何事实；
// 单条事实不合格只丢弃该条（NormalizeFact 同口径），不影响其余条目。
func ParseConcludeOutput(text string) (*ConcludeEnvelope, error) {
	raw := strings.TrimSpace(text)
	if raw == "" {
		return nil, fmt.Errorf("收尾回复为空")
	}
	var lastErr error
	for _, cand := range concludeJSONCandidates(raw) {
		cand = strings.TrimSpace(cand)
		if !strings.Contains(cand, `"facts"`) {
			continue
		}
		var env ConcludeEnvelope
		if err := json.Unmarshal([]byte(cand), &env); err != nil {
			lastErr = err
			continue
		}
		out := &ConcludeEnvelope{Residual: strings.TrimSpace(env.Residual)}
		for _, f := range env.Facts {
			if len(out.Facts) >= ConcludeMaxFacts {
				break
			}
			f.Category = concludeCategoryFromKey(f.FactKey)
			nf, err := NormalizeFact(f)
			if err != nil {
				continue
			}
			out.Facts = append(out.Facts, nf)
		}
		return out, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("收尾信封解析失败: %w", lastErr)
	}
	return nil, fmt.Errorf("回复中未找到含 facts 字段的 JSON 信封")
}

// concludeCategoryFromKey 从 fact_key 前缀推导 category（NormalizeFact 已保证键形合法）。
func concludeCategoryFromKey(key string) string {
	parts := strings.SplitN(strings.TrimSpace(key), "/", 2)
	return parts[0]
}

// concludeJSONCandidates 产出按可信度排序的 JSON 候选文本（围栏块最可信，其次顶层
// 平衡对象，最后整段兜底）。围栏块按出现序；未闭合围栏按已有内容收（截断兜底）。
func concludeJSONCandidates(text string) []string {
	out := concludeFencedBlocks(text)
	out = append(out, concludeTopLevelObjects(text)...)
	out = append(out, text)
	return out
}

// concludeFencedBlocks 提取 ``` 围栏块内容（语言标记行随围栏行丢弃）。
func concludeFencedBlocks(text string) []string {
	var out []string
	var buf []string
	in := false
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		if !in && strings.HasPrefix(t, "```") {
			in = true
			buf = buf[:0]
			continue
		}
		if in && strings.HasPrefix(t, "```") {
			in = false
			if len(buf) > 0 {
				out = append(out, strings.Join(buf, "\n"))
			}
			continue
		}
		if in {
			buf = append(buf, ln)
		}
	}
	if in && len(buf) > 0 {
		out = append(out, strings.Join(buf, "\n"))
	}
	return out
}

// concludeTopLevelObjects 提取文本中的顶层平衡 {...} 对象（跳过字符串字面量内的花括号）。
func concludeTopLevelObjects(text string) []string {
	var out []string
	depth := 0
	start := -1
	inStr := false
	esc := false
	for i, r := range text {
		if inStr {
			if esc {
				esc = false
				continue
			}
			if r == '\\' {
				esc = true
				continue
			}
			if r == '"' {
				inStr = false
			}
			continue
		}
		switch r {
		case '"':
			inStr = true
		case '{':
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth > 0 {
				depth--
				if depth == 0 && start >= 0 {
					out = append(out, text[start:i+len("}")])
					start = -1
				}
			}
		}
	}
	return out
}
