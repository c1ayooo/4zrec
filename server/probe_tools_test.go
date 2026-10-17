package server

import (
	"context"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/c1ayooo/4zrec/httpprobe"
	"github.com/c1ayooo/4zrec/traffic"
)

func TestRecordProbeEvidence(t *testing.T) {
	tr, err := traffic.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	s := &Server{m: &Manager{traffic: tr}}
	res := &httpprobe.Result{
		StatusCode:   200,
		StatusText:   "200 OK",
		RequestText:  "GET /x HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
		ResponseText: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Test: 1\r\n\r\nhello",
		RespHeaders:  http.Header{"Content-Type": []string{"text/plain"}, "X-Test": []string{"1"}},
		FinalURL:     "https://example.com/x",
	}
	id := s.recordProbeEvidence(res, "GET", "https://example.com/x", "")
	if id == "" {
		t.Fatal("empty traffic id")
	}
	var got *traffic.EvidenceExchange
	err = tr.ReadEvidence(context.Background(), []string{id}, func(e traffic.EvidenceExchange) error {
		got = &e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Status != 200 || got.URL != "https://example.com/x" {
		t.Fatalf("evidence = %+v", got)
	}
	body, err := io.ReadAll(got.Response)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Fatalf("response body = %q", body)
	}
	if got.ReqHead == "" || got.RespHead == "" {
		t.Fatalf("heads not preserved: %q / %q", got.ReqHead, got.RespHead)
	}
}

func TestRecordProbeEvidenceUsesFullBodyFile(t *testing.T) {
	tr, err := traffic.Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	s := &Server{m: &Manager{traffic: tr}}
	full := make([]byte, 300*1024)
	for i := range full {
		full[i] = byte(i % 251)
	}
	path := t.TempDir() + "/big.pdf"
	if err := os.WriteFile(path, full, 0o644); err != nil {
		t.Fatal(err)
	}
	res := &httpprobe.Result{
		StatusCode:   200,
		RequestText:  "GET /big.pdf HTTP/1.1\r\nHost: example.com\r\n\r\n",
		ResponseText: "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\r\n%PDF",
		RespHeaders:  http.Header{"Content-Type": []string{"application/pdf"}},
		FinalURL:     "https://example.com/big.pdf",
	}
	id := s.recordProbeEvidence(res, "GET", "https://example.com/big.pdf", path)
	if id == "" {
		t.Fatal("empty traffic id")
	}
	if err := tr.ReadEvidence(context.Background(), []string{id}, func(e traffic.EvidenceExchange) error {
		if e.RespLen != int64(len(full)) {
			t.Fatalf("resp_len = %d, want %d", e.RespLen, len(full))
		}
		body, err := io.ReadAll(e.Response)
		if err != nil {
			return err
		}
		if len(body) != len(full) {
			t.Fatalf("body len = %d, want %d", len(body), len(full))
		}
		if body[0] != full[0] || body[len(body)-1] != full[len(full)-1] {
			t.Fatal("body content mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSplitHTTPHeadBody(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantHead string
		wantBody string
	}{
		{
			name:     "crlf",
			raw:      "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc",
			wantHead: "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 3",
			wantBody: "abc",
		},
		{
			name:     "lf",
			raw:      "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nhello",
			wantHead: "HTTP/1.1 200 OK\nContent-Type: text/plain",
			wantBody: "hello",
		},
		{
			name:     "no-body",
			raw:      "GET / HTTP/1.1\r\nHost: a\r\n\r\n",
			wantHead: "GET / HTTP/1.1\r\nHost: a",
			wantBody: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			head, body := splitHTTPHeadBody(tc.raw)
			if head != tc.wantHead || string(body) != tc.wantBody {
				t.Fatalf("got head=%q body=%q; want head=%q body=%q", head, body, tc.wantHead, tc.wantBody)
			}
		})
	}
}
