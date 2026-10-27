package poc

import (
	"encoding/json"
	"fmt"
	"strings"
)

// extractJSONObject returns the first balanced JSON object in s, tolerating
// markdown fences and model prose around it. Models routinely wrap the answer
// in ```json blocks, and generated PoC code contains braces and quotes, so the
// scanner tracks string state and escapes instead of counting braces blindly.
func extractJSONObject(s string) string {
	s = strings.ReplaceAll(s, "```json", "")
	s = strings.ReplaceAll(s, "```", "")
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return ""
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case c == '\\' && inString:
			escaped = true
		case c == '"':
			inString = !inString
		case inString:
			// Braces inside a string literal are data, not structure.
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// unmarshalLoose decodes the first JSON object found in a model reply.
func unmarshalLoose(raw string, out any) error {
	obj := extractJSONObject(raw)
	if obj == "" {
		return fmt.Errorf("模型响应中没有 JSON 对象")
	}
	if err := json.Unmarshal([]byte(obj), out); err != nil {
		return fmt.Errorf("解析模型 JSON: %w", err)
	}
	return nil
}

// containsHan reports whether s contains a Chinese character.
func containsHan(s string) bool {
	for _, r := range s {
		if r >= 0x4E00 && r <= 0x9FFF {
			return true
		}
	}
	return false
}
