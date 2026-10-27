package session_test

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/adapters/httpx"
	"github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/gates"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/flow/session"
)

// fakeWSMan is a minimal WSMan listener: it mints a shell id, runs whatever
// command it is handed by echoing the marker back, and reports Done.
func fakeWSMan(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if !strings.Contains(r.Header.Get("Content-Type"), "soap+xml") {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("missing Authorization header")
		}
		raw, _ := io.ReadAll(r.Body)
		body := string(raw)
		w.Header().Set("Content-Type", `application/soap+xml;charset=UTF-8`)
		switch {
		case strings.Contains(body, "rsp:Shell"):
			_, _ = w.Write([]byte(envelope(
				`<rsp:Shell><rsp:ShellId>shell-42</rsp:ShellId></rsp:Shell>`)))
		case strings.Contains(body, "rsp:CommandLine"):
			_, _ = w.Write([]byte(envelope(
				`<rsp:CommandResponse><rsp:CommandId>cmd-7</rsp:CommandId></rsp:CommandResponse>`)))
		case strings.Contains(body, "rsp:Receive"):
			out := base64.StdEncoding.EncodeToString([]byte("winrm-output-marker"))
			errOut := base64.StdEncoding.EncodeToString([]byte("warn"))
			_, _ = w.Write([]byte(envelope(
				`<rsp:ReceiveResponse>` +
					`<rsp:Stream Name="stdout" CommandId="cmd-7">` + out + `</rsp:Stream>` +
					`<rsp:Stream Name="stderr" CommandId="cmd-7">` + errOut + `</rsp:Stream>` +
					`<rsp:CommandState CommandId="cmd-7" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">` +
					`<rsp:ExitCode>3</rsp:ExitCode></rsp:CommandState>` +
					`</rsp:ReceiveResponse>`)))
		case strings.Contains(body, "rsp:Delete"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(envelope("")))
		default:
			t.Errorf("unexpected WSMan request: %s", body)
		}
	}))
}

func envelope(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">` +
		`<s:Body>` + body + `</s:Body></s:Envelope>`
}

func TestWinRMSessionExec(t *testing.T) {
	srv := fakeWSMan(t)
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)

	scope := gates.StaticScope(host)
	lim := gates.NewLimiter()
	httpClient := httpx.New(scope, lim, nil)
	m := session.NewManager(nil, nil)
	m.RegisterOpener("winrm", &session.WinRMOpener{HTTP: httpClient, Port: port})

	info, err := m.Open(context.Background(), core.SessionSpec{
		Kind: "winrm", Host: host, User: "Administrator", Secret: "pw",
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != "winrm" || info.Meta["shell_id"] != "shell-42" {
		t.Fatalf("info = %+v", info)
	}
	s, _ := m.Get(info.ID)
	out, err := s.Exec(context.Background(), "whoami", core.ExecOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Stdout, "winrm-output-marker") {
		t.Fatalf("stdout = %q", out.Stdout)
	}
	if !strings.Contains(out.Stderr, "warn") {
		t.Fatalf("stderr = %q", out.Stderr)
	}
	if out.ExitCode != 3 {
		t.Fatalf("exit = %d, want 3", out.ExitCode)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestWinRMOpenerFailClosedWithoutHTTP(t *testing.T) {
	o := &session.WinRMOpener{}
	if _, err := o.Open(context.Background(), core.SessionSpec{Kind: "winrm", Host: "127.0.0.1"}); err == nil {
		t.Fatal("WinRM opener without HTTPDoer must fail closed")
	}
}

func TestWinRMScopeDenied(t *testing.T) {
	srv := fakeWSMan(t)
	defer srv.Close()
	host, port := splitHostPort(t, srv.URL)
	scope := gates.StaticScope("10.0.0.1") // not the test host
	httpClient := httpx.New(scope, gates.NewLimiter(), nil)
	o := &session.WinRMOpener{HTTP: httpClient, Port: port}
	if _, err := o.Open(context.Background(), core.SessionSpec{Kind: "winrm", Host: host}); err == nil {
		t.Fatal("out-of-scope WinRM target must be denied")
	}
}

// splitHostPort turns an httptest URL into the host and port a session spec
// needs.
func splitHostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	rest := strings.TrimPrefix(strings.TrimPrefix(raw, "http://"), "https://")
	i := strings.LastIndex(rest, ":")
	if i < 0 {
		t.Fatalf("no port in %q", raw)
	}
	port, err := strconv.Atoi(rest[i+1:])
	if err != nil {
		t.Fatalf("bad port in %q: %v", raw, err)
	}
	return rest[:i], port
}
