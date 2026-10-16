package httpprobe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoRequest_MultipartUpload(t *testing.T) {
	var gotType, gotFile, gotField, gotForm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			t.Errorf("解析 multipart 失败: %v", err)
			return
		}
		gotField = r.MultipartForm.File["file"][0].Filename
		gotForm = r.FormValue("note")
		f, _ := r.MultipartForm.File["file"][0].Open()
		defer f.Close()
		buf := make([]byte, 5)
		_, _ = f.Read(buf)
		gotFile = string(buf)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	dir := t.TempDir()
	p := filepath.Join(dir, "shell.php")
	if err := os.WriteFile(p, []byte("<?php echo 1;"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := DoRequest(context.Background(), Request{
		Method:     "POST",
		URL:        srv.URL + "/upload",
		UploadFile: p,
		FormFields: map[string]string{"note": "poc"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotType, "multipart/form-data") {
		t.Errorf("Content-Type 应为 multipart: %s", gotType)
	}
	if gotField != "shell.php" || gotForm != "poc" || gotFile != "<?php" {
		t.Errorf("multipart 内容错误: field=%s form=%s file=%q", gotField, gotForm, gotFile)
	}
	// 报文里应能看到 multipart 头与字段
	if !strings.Contains(res.Transcript, "multipart/form-data") {
		t.Error("报文未包含 multipart 头")
	}
}

func TestDoRequest_FollowRedirectsToggle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/a" {
			w.Header().Set("Location", "/b")
			w.WriteHeader(302)
			return
		}
		_, _ = w.Write([]byte("final"))
	}))
	defer srv.Close()

	follow := true
	res, err := DoRequest(context.Background(), Request{URL: srv.URL + "/a", FollowRedirects: follow})
	if err != nil || !strings.Contains(res.RespBody, "final") {
		t.Fatalf("显式 follow_redirects=true 应跟随跳转: err=%v body=%q", err, res.RespBody)
	}

	noFollow := false
	res2, err := DoRequest(context.Background(), Request{URL: srv.URL + "/a", FollowRedirects: noFollow})
	if err != nil {
		t.Fatal(err)
	}
	if res2.StatusCode != 302 || !strings.Contains(res2.ResponseText, "302") || strings.Contains(res2.RespBody, "final") {
		t.Errorf("不跟随应捕获原始 302: status=%d body=%q", res2.StatusCode, res2.RespBody)
	}
}

func TestDoRequest_UserAgentExposed(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	res, err := DoRequest(context.Background(), Request{URL: srv.URL, Headers: map[string]string{"User-Agent": "UA-Probe-Test/1.0"}})
	if err != nil {
		t.Fatal(err)
	}
	if gotUA != "UA-Probe-Test/1.0" || res.UserAgent != "UA-Probe-Test/1.0" {
		t.Errorf("实际 UA 未透出: got=%q result=%q", gotUA, res.UserAgent)
	}
}
