package guard

import (
	"context"
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
