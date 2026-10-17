package traffic

import (
	"context"
	"io"
	"testing"
)

func TestRecordEvidenceRoundTrip(t *testing.T) {
	tr, err := Open(t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	const (
		reqHead  = "POST /a?b=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n"
		respHead = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Test: yes\r\n"
	)
	id, err := tr.RecordEvidence(EvidenceRecord{
		URL:      "https://example.com/a?b=1",
		Method:   "POST",
		Status:   200,
		ReqHead:  reqHead,
		ReqBody:  []byte(`{"x":1}`),
		RespHead: respHead,
		RespBody: []byte(`{"ok":true}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("empty evidence id")
	}

	var got *EvidenceExchange
	err = tr.ReadEvidence(context.Background(), []string{id}, func(e EvidenceExchange) error {
		got = &e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("evidence not read back")
	}
	if got.URL != "https://example.com/a?b=1" || got.Method != "POST" || got.Status != 200 {
		t.Fatalf("metadata = %+v", got)
	}
	if got.ContentType != "application/json" {
		t.Fatalf("content type = %q", got.ContentType)
	}
	if got.ReqLen != int64(len(`{"x":1}`)) || got.RespLen != int64(len(`{"ok":true}`)) {
		t.Fatalf("lengths = %d/%d", got.ReqLen, got.RespLen)
	}
	req, err := io.ReadAll(got.Request)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := io.ReadAll(got.Response)
	if err != nil {
		t.Fatal(err)
	}
	if string(req) != `{"x":1}` {
		t.Fatalf("request body = %q", req)
	}
	if string(resp) != `{"ok":true}` {
		t.Fatalf("response body = %q", resp)
	}
	if got.ReqHead != reqHead {
		t.Fatalf("request head = %q", got.ReqHead)
	}
	if got.RespHead != respHead {
		t.Fatalf("response head = %q", got.RespHead)
	}
}
