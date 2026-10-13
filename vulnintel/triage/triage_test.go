package triage

import (
	"testing"
)

// TestSelfCheckVerdicts 六个验收场景的回归保护
func TestSelfCheckVerdicts(t *testing.T) {
	for _, c := range SelfCheck() {
		if !c.Pass {
			t.Errorf("场景 %s 失败：期望 %v，实际 %s（总分 %d）", c.Name, c.Expect, c.Got, c.Score)
		}
	}
}

func TestShouldAlert(t *testing.T) {
	for v, want := range map[Verdict]bool{
		VerdictACT: true, VerdictMalicious: true,
		VerdictWatch: false, VerdictNoise: false, VerdictLabOnly: false,
	} {
		if got := ShouldAlert(v); got != want {
			t.Errorf("ShouldAlert(%s) = %v, want %v", v, got, want)
		}
	}
}

func TestParseCVSS(t *testing.T) {
	cases := []struct {
		name    string
		vector  string
		wantKey map[string]string
		version string
	}{
		{"v3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", map[string]string{"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}, "3.1"},
		{"v3.1 temporal", "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:L/E:U/RL:OF/RC:C", map[string]string{"AV": "N", "AC": "H", "E": "U", "RL": "OF"}, "3.1"},
		{"v2", "AV:N/AC:M/Au:N/C:P/I:P/A:P", map[string]string{"AV": "N", "AC": "M", "AU": "N", "C": "P", "I": "P", "A": "P"}, "2.0"},
		{"v2 temporal", "AV:L/AC:H/Au:S/C:C/I:C/A:C/E:POC/RL:TF/RC:UC", map[string]string{"AV": "L", "AU": "S", "E": "POC"}, "2.0"},
		{"v4", "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", map[string]string{"AV": "N", "AC": "L", "AT": "P", "UI": "N", "VC": "H"}, "4.0"},
		{"小写兼容", "cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h", map[string]string{"AV": "N", "C": "H"}, "3.1"},
	}
	for _, tc := range cases {
		m := ParseCVSS(tc.vector)
		if m.Version != tc.version {
			t.Errorf("%s: version = %q, want %q", tc.name, m.Version, tc.version)
		}
		for k, want := range tc.wantKey {
			if got := m.Get(k); got != want {
				t.Errorf("%s: %s = %q, want %q", tc.name, k, got, want)
			}
		}
	}

	bad := []string{"", "not-a-vector", "CVSS:3.1/AV:N/坏段/AC:L", "AV:/AC:L"}
	for _, b := range bad {
		if m := ParseCVSS(b); len(m.M) != 0 {
			t.Errorf("ParseCVSS(%q) 应返回空指标集，实际 %v", b, m.M)
		}
	}
}

// TestRescueRule 单独验证「高危漏洞 + 垃圾 PoC」抢救线：CVE 分够高时垃圾仓库绝不触发丢弃
func TestRescueRule(t *testing.T) {
	cve := CVEMeta{
		CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		EPSS:       fptr(0.6), CWE: []int{89}, Automatable: bptr(true),
		Description: "Unauthenticated SQL injection leading to remote code execution.",
	}
	repo := RepoMeta{FullName: "spam/cve-x-checker", Stars: 0, Forks: 0,
		Files: []FileEntry{{Path: "README.md", Size: 100}}}
	v, _, reasons := Triage(cve, repo)
	if v != VerdictWatch {
		t.Errorf("高危漏洞 + 垃圾仓库应 WATCH（观察而不是丢弃），实际 %s", v)
	}
	found := false
	for _, r := range reasons {
		if contains(r, "不要丢弃") {
			found = true
		}
	}
	if !found {
		t.Error("WATCH 理由中应包含「不要丢弃」提示")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
