package vulnkb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCoverageAgainstLocalKB 是开发期干跑:对本地 vulnkb/ 全量解析并统计
// 字段覆盖率,不碰数据库。目录不存在时跳过(CI/其他环境无此资产)。
func TestCoverageAgainstLocalKB(t *testing.T) {
	root := "../vulnkb" // 测试 CWD 是包目录;运行时默认目录相对服务工作目录
	st, err := os.Stat(root)
	if err != nil || !st.IsDir() {
		t.Skip("no local vulnkb/ dir")
	}
	var total, withProduct, withType, withCVE, withFP, withReq, withPayload int
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".md") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		e := Parse(raw, path)
		total++
		if e.Product != "" {
			withProduct++
		}
		if e.VulnType != "" {
			withType++
		}
		if e.CVE != "" {
			withCVE++
		}
		if e.Fingerprint != "" {
			withFP++
		}
		if e.RequestLine != "" {
			withReq++
		}
		if e.Payload != "" {
			withPayload++
		}
		return nil
	})
	if total == 0 {
		t.Skip("empty dir")
	}
	t.Logf("total=%d product=%.1f%% type=%.1f%% cve=%.1f%% fingerprint=%.1f%% request=%.1f%% payload=%.1f%%",
		total,
		pct(withProduct, total), pct(withType, total), pct(withCVE, total),
		pct(withFP, total), pct(withReq, total), pct(withPayload, total))
}

func pct(n, total int) float64 { return float64(n) * 100 / float64(total) }
