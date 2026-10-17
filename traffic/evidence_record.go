package traffic

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/c1ayooo/4zrec/db"
)

// EvidenceRecord is one complete request/response pair produced by a platform
// tool (http_probe) rather than the recording proxy. Heads must contain the
// request/status line and headers only; bodies are passed separately so the same
// inline/blob split as recorded proxy traffic applies.
type EvidenceRecord struct {
	URL         string
	Method      string
	Status      int
	ContentType string
	ReqHead     string
	ReqBody     []byte
	RespHead    string
	RespBody    []byte
	CapturedAt  time.Time
}

// RecordEvidence persists one tool-generated exchange into the same index and
// blob store as proxied traffic, so it can be searched, bound to a finding and
// exported like any other packet. It works independently of the capture switch:
// recording an explicit tool call is evidence preservation, not passive capture.
func (t *Traffic) RecordEvidence(e EvidenceRecord) (string, error) {
	if t == nil {
		return "", errors.New("流量录制存储不可用")
	}
	rawURL := strings.TrimSpace(e.URL)
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("无效的证据 URL: %q", e.URL)
	}
	method := strings.ToUpper(strings.TrimSpace(e.Method))
	if method == "" {
		method = "GET"
	}
	at := e.CapturedAt
	if at.IsZero() {
		at = time.Now()
	}
	reqHead := ensureTrailingNewline(e.ReqHead)
	respHead := ensureTrailingNewline(e.RespHead)
	ct := strings.TrimSpace(e.ContentType)
	if ct == "" {
		ct = headerValue(respHead, "Content-Type")
	}
	reqCT := headerValue(reqHead, "Content-Type")

	// Evidence written by a separate process (backfill, CLI) must not collide
	// with the recorder's "<unix>-<seq>" ids, so keep a distinct prefix.
	n := t.seq.Add(1)
	id := fmt.Sprintf("ev-%d-%04d", at.UnixNano(), n%10000)

	t.wmu.Lock()
	defer t.wmu.Unlock()
	reqBody := t.spill(e.ReqBody, reqCT)
	respBody := t.spill(e.RespBody, ct)

	tx, err := t.db.Begin()
	if err != nil {
		return "", fmt.Errorf("开启证据事务: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	res, err := tx.Exec(`INSERT INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`,
		id, at.Unix(), u.Hostname(), method, db.TemplatePath(u.EscapedPath()), u.String(),
		e.Status, ct, len(e.ReqBody), len(e.RespBody))
	if err != nil {
		return "", fmt.Errorf("写证据索引: %w", err)
	}
	rowid, err := res.LastInsertId()
	if err != nil {
		return "", fmt.Errorf("取证据 rowid: %w", err)
	}
	if _, err = tx.Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`,
		id, reqHead, reqBody.inline, nullIfEmpty(reqBody.hash),
		respHead, respBody.inline, nullIfEmpty(respBody.hash)); err != nil {
		return "", fmt.Errorf("写证据正文: %w", err)
	}
	for _, h := range []string{reqBody.hash, respBody.hash} {
		if h == "" {
			continue
		}
		if _, err = tx.Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, h, id); err != nil {
			return "", fmt.Errorf("登记证据 blob: %w", err)
		}
	}
	if t.fts {
		idx := strings.Join([]string{u.String(), reqHead, reqBody.index, respHead, respBody.index}, "\n")
		if _, err = tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowid, idx); err != nil {
			return "", fmt.Errorf("写证据全文索引: %w", err)
		}
	}
	if err = tx.Commit(); err != nil {
		return "", fmt.Errorf("提交证据: %w", err)
	}
	return id, nil
}

func ensureTrailingNewline(s string) string {
	if s == "" || strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

// headerValue returns the first case-insensitive header value from a raw head
// block (request or response). It intentionally ignores the first line.
func headerValue(head, name string) string {
	for _, line := range strings.Split(head, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
