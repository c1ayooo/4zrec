package poc

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// strutsIntel is the advisory fixture the assembly tests ground against: its
// text mentions the entry path, the parameter name and the response marker, so
// a spec quoting them is grounded.
func strutsIntel() IntelInput {
	return IntelInput{
		Title:       "Apache Struts2 文件上传 OGNL 注入",
		Description: "攻击者可以向 /upload.action 发送带 OGNL 表达式的上传请求，服务端把参数名当表达式解析。",
		Severity:    "critical",
		CVE:         "CVE-2024-53677",
		Tags:        []string{"Struts2", "OGNL"},
		Affected:    []string{"maven/org.apache.struts:struts2-core"},
	}
}

func strutsCorpus() string { return intelCorpus(strutsIntel()) }

func TestBuildPoCScriptAssemblesGroundedElements(t *testing.T) {
	code, note, err := buildPoCScript(strutsIntel(), strutsCorpus(), PoCSpec{
		Constructible: true,
		Method:        "POST",
		Path:          "/upload.action",
		Params:        []PoCParam{{Name: "OGNL", Value: "test"}},
		Marker:        "OGNL",
		Evidence:      "上传接口把参数名当 OGNL 表达式解析",
	})
	if err != nil {
		t.Fatalf("buildPoCScript: %v", err)
	}
	if note != "" {
		t.Fatalf("all elements were grounded, note should be empty: %q", note)
	}
	// The script must be dependency-free: a probe the operator cannot run on a
	// target-adjacent box is not a verification script.
	if strings.Contains(code, "import requests") {
		t.Fatal("the skeleton must not depend on a third-party HTTP library")
	}
	for _, want := range []string{
		"PATH = \"/upload.action\"",
		"METHOD = \"POST\"",
		"BODY_FORMAT = \"form\"",
		"PARAMS = {\"OGNL\": \"test\"}",
		"EXPECT_WORDS = [\"OGNL\"]",
		"EXPECT_STATUS = 0",
		"urllib.request.urlopen",
	} {
		if !strings.Contains(code, want) {
			t.Fatalf("script missing %q:\n%s", want, code)
		}
	}
}

func TestBuildPoCScriptRefusesUngroundedPath(t *testing.T) {
	_, _, err := buildPoCScript(strutsIntel(), strutsCorpus(), PoCSpec{
		Constructible: true, Method: "POST", Path: "/admin/uploadv9",
		Params: []PoCParam{{Name: "OGNL", Value: "x"}}, Marker: "OGNL",
	})
	if err == nil || !strings.Contains(err.Error(), "找不到出处") {
		t.Fatalf("err = %v, want an ungrounded-path refusal", err)
	}
}

func TestBuildPoCScriptRefusesBarePath(t *testing.T) {
	_, _, err := buildPoCScript(strutsIntel(), strutsCorpus(), PoCSpec{
		Constructible: true, Method: "GET", Path: "/",
		Params: []PoCParam{{Name: "OGNL", Value: "x"}}, Marker: "OGNL",
	})
	if err == nil || !strings.Contains(err.Error(), "入口路径") {
		t.Fatalf("err = %v, want an entry-path refusal", err)
	}
}

func TestBuildPoCScriptRefusesUngroundedMarker(t *testing.T) {
	_, _, err := buildPoCScript(strutsIntel(), strutsCorpus(), PoCSpec{
		Constructible: true, Method: "GET", Path: "/upload.action",
		Params: []PoCParam{{Name: "OGNL", Value: "x"}}, Marker: "root:x:0:0",
	})
	if err == nil || !strings.Contains(err.Error(), "响应特征") {
		t.Fatalf("err = %v, want an ungrounded-marker refusal", err)
	}
}

// TestBuildPoCScriptNotesUngroundedParams pins the asymmetry: a parameter name
// that the advisory does not spell out is a caveat for the operator, not a
// refusal, because the obvious name for a documented endpoint is still usable.
func TestBuildPoCScriptNotesUngroundedParams(t *testing.T) {
	code, note, err := buildPoCScript(strutsIntel(), strutsCorpus(), PoCSpec{
		Constructible: true, Method: "GET", Path: "/upload.action",
		Params:      []PoCParam{{Name: "OGNL", Value: "x"}, {Name: "top.abcdef", Value: "y"}},
		MatchStatus: 200,
	})
	if err != nil {
		t.Fatalf("buildPoCScript: %v", err)
	}
	if !strings.Contains(note, "1 个参数名") {
		t.Fatalf("note = %q, want one ungrounded parameter reported", note)
	}
	if !strings.Contains(code, "# 注意：1 个参数名") {
		t.Fatalf("script header should carry the caveat:\n%s", code)
	}
}

func TestBuildPoCScriptStatusOnlyVerdict(t *testing.T) {
	code, _, err := buildPoCScript(strutsIntel(), strutsCorpus(), PoCSpec{
		Constructible: true, Method: "GET", Path: "/upload.action",
		Params: []PoCParam{{Name: "OGNL", Value: "x"}}, MatchStatus: 200,
	})
	if err != nil {
		t.Fatalf("buildPoCScript: %v", err)
	}
	if !strings.Contains(code, "EXPECT_STATUS = 200") {
		t.Fatalf("expected status should be set:\n%s", code)
	}
	if !strings.Contains(code, "EXPECT_WORDS = []") {
		t.Fatalf("no marker was given, the word list should be empty:\n%s", code)
	}
}

func TestBuildPoCScriptJSONBodyAndOutOfRangeStatus(t *testing.T) {
	code, _, err := buildPoCScript(strutsIntel(), strutsCorpus(), PoCSpec{
		Constructible: true, Method: "POST", Path: "/upload.action",
		Params: []PoCParam{{Name: "OGNL", Value: "x"}}, BodyFormat: "json",
		Marker: "OGNL", MatchStatus: 9999,
	})
	if err != nil {
		t.Fatalf("buildPoCScript: %v", err)
	}
	if !strings.Contains(code, "BODY_FORMAT = \"json\"") {
		t.Fatalf("json body format should survive:\n%s", code)
	}
	// An impossible status is dropped rather than embedded: a script asserting
	// HTTP 9999 can never confirm anything.
	if !strings.Contains(code, "EXPECT_STATUS = 0") {
		t.Fatalf("an out-of-range status must be dropped:\n%s", code)
	}
}

func TestBuildPoCScriptEscapesLiterals(t *testing.T) {
	in := IntelInput{Title: "quoted", Description: `the "/x.action" endpoint quotes "OGNL"`}
	code, _, err := buildPoCScript(in, intelCorpus(in), PoCSpec{
		Constructible: true, Method: "GET", Path: "/x.action",
		Params: []PoCParam{{Name: "OGNL", Value: `a"b\c`}}, Marker: "OGNL",
	})
	if err != nil {
		t.Fatalf("buildPoCScript: %v", err)
	}
	if !strings.Contains(code, `"a\"b\\c"`) {
		t.Fatalf("parameter values must be escaped for Python:\n%s", code)
	}
}

// TestGeneratedScriptCompiles pins that the assembled script is real Python,
// not a string that merely contains the expected tokens. python3 is optional
// in CI, so the test skips rather than fails when it is absent.
func TestGeneratedScriptCompiles(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	code, _, err := buildPoCScript(strutsIntel(), strutsCorpus(), PoCSpec{
		Constructible: true, Method: "POST", Path: "/upload.action",
		Params: []PoCParam{{Name: "OGNL", Value: "test"}}, Marker: "OGNL",
	})
	if err != nil {
		t.Fatalf("buildPoCScript: %v", err)
	}
	path := filepath.Join(t.TempDir(), "poc.py")
	if err := os.WriteFile(path, []byte(code), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	out, err := exec.Command(python, "-m", "py_compile", path).CombinedOutput()
	if err != nil {
		t.Fatalf("generated script is not valid Python: %v\n%s\n---\n%s", err, out, code)
	}
}

func TestValidatePoCScriptRejectsShellSkeleton(t *testing.T) {
	if err := ValidatePoCScript("print('not a poc')\n"); err == nil {
		t.Fatal("a skeleton without a request must be rejected")
	}
}

func TestPathGroundedAcceptsDocumentedTailSegment(t *testing.T) {
	corpus := intelCorpus(strutsIntel())
	if !pathGrounded(corpus, "/api/v2/upload.action") {
		t.Fatal("a path whose tail segment is documented should be grounded")
	}
	if pathGrounded(corpus, "/api") {
		t.Fatal("a two-character tail segment is not evidence")
	}
}
