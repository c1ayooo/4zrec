package guard

import (
	"context"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/toolface/intercept"
)

func TestSimpleHTTPFetch(t *testing.T) {
	cases := map[string]bool{
		`curl -s http://127.0.0.1:19090/api/system/config`:       true,
		`curl -X POST -d '{"a":1}' http://127.0.0.1:19090/api/x`: true,
		`wget http://127.0.0.1:19090/`:                           true,
		`curl -o out.html http://127.0.0.1:19090/`:               true,
		`sudo curl -s http://127.0.0.1:19090/`:                   true,
		`curl -K curl.cfg http://127.0.0.1:19090/`:               false,
		`curl --version`: false,
		`curl -s http://127.0.0.1:19090/ | grep title`:           false,
		`curl -s http://127.0.0.1:19090/ > out`:                  false,
		`python3 -c 'import requests; requests.get("http://x")'`: false,
	}
	for cmd, want := range cases {
		if got := simpleHTTPFetch(cmd); got != want {
			t.Errorf("simpleHTTPFetch(%q) = %v, want %v", cmd, got, want)
		}
	}
}

func TestHTTPProbePolicyViolation(t *testing.T) {
	ctx := intercept.WithTaskContext(context.Background(), "173", "worker · #1", nil)
	if got := httpProbePolicyViolation(ctx, "Bash", `curl -s http://127.0.0.1:19090/api/system/config`); got == "" {
		t.Fatal("simple curl in worker context should be blocked")
	}
	if got := httpProbePolicyViolation(ctx, "Bash", `curl -s http://127.0.0.1:19090/ | grep title`); got != "" {
		t.Fatal("pipeline curl must remain allowed")
	}
	if got := httpProbePolicyViolation(context.Background(), "Bash", `curl -s http://127.0.0.1:19090/`); got != "" {
		t.Fatal("no task context should not enforce the policy")
	}
	ctxMain := intercept.WithTaskContext(context.Background(), "173", "mainagent", nil)
	if got := httpProbePolicyViolation(ctxMain, "Bash", `curl -s http://127.0.0.1:19090/`); got != "" {
		t.Fatal("mainagent should not be blocked (http_probe may be unbound)")
	}
}

func TestLoopSimpleFetch(t *testing.T) {
	cases := map[string]bool{
		// 批量循环:循环体里的简单 curl/wget 是 requests[] 的场景 → 拦。
		`for u in a.example.com b.example.com; do curl -s http://$u; done`: true,
		"for u in $ZREC_TARGETS; do\n  curl -s http://$u/\n done":          true,
		`while read u; do curl "$u"; done < urls.txt`:                      true,
		`for p in 1 2 3; do wget -q http://t.example.com/?id=$p; done`:     true,
		`for h in $ZREC_TARGETS; do nmap -p 80 $h; done`:                   false, // 非 HTTP 工具不拦
		`for u in a.example.com; do curl -s http://$u | grep title; done`:  false, // 管道例外
		`while read u; do curl -s "$u" > "out-$u.html"; done < list`:       false, // 重定向例外
		`for u in a b; do curl http://$(make-url $u); done`:                false, // 命令替换例外
		`for f in *.json; do jq . "$f" > /dev/null; done`:                  false, // 本地循环不拦
		`curl -s http://127.0.0.1/api && echo done`:                        false, // 无循环体
		`echo do; curl -s http://127.0.0.1/`:                               false, // 无 done 配对
		`for u in a b; do dig +short $u; done`:                             false, // 非 curl/wget
		"for u in a b\ndo\n# 前置本地处理\ncurl -s http://$u/\ndone":             true,  // 多语句循环体
	}
	for cmd, want := range cases {
		if got := loopSimpleFetch(cmd); got != want {
			t.Errorf("loopSimpleFetch(%q) = %v, want %v", cmd, got, want)
		}
	}
}

// TestHTTPProbePolicyViolationLoop 循环批量的拦截文案必须指到 requests[]/template。
func TestHTTPProbePolicyViolationLoop(t *testing.T) {
	ctx := intercept.WithTaskContext(context.Background(), "173", "worker · #1", nil)
	got := httpProbePolicyViolation(ctx, "Bash", `for u in a.example.com b.example.com; do curl -s http://$u; done`)
	if got == "" {
		t.Fatal("batch loop should be blocked")
	}
	if !strings.Contains(got, "requests") || !strings.Contains(got, "template") {
		t.Fatalf("loop message should point to batch modes, got: %s", got)
	}
}
