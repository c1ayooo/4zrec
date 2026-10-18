package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capability/vuln/nuclei"
)

const testCustomTemplateYAML = `id: custom-api
info:
  name: Custom API Check
  author: 4zrec
  severity: medium
  tags: custom
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`

func newNucleiTestServer(t *testing.T) *Server {
	t.Helper()
	s := &Server{dataDir: t.TempDir()}
	dir := filepath.Join(s.dataDir, "nuclei", "templates", "http")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "official.yaml"), []byte(`
id: official-api
info:
  name: Official API Check
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	return s
}

func performJSON(t *testing.T, s *Server, method, target string, body any, id string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, target, &buf)
	if id != "" {
		req.SetPathValue("id", id)
	}
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestNucleiTemplateAPI(t *testing.T) {
	s := newNucleiTestServer(t)

	// 官方列表
	rec := performJSON(t, s, http.MethodGet, "/api/nuclei/templates?source=official", nil, "", s.getNucleiTemplates)
	if rec.Code != 200 {
		t.Fatalf("list status = %d: %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Items []nuclei.TemplateMeta `json:"items"`
		Total int                   `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 || len(list.Items) != 1 || list.Items[0].Source != nuclei.SourceOfficial {
		t.Fatalf("official list = %+v", list)
	}

	// 创建自定义
	rec = performJSON(t, s, http.MethodPost, "/api/nuclei/templates", map[string]string{"yaml": testCustomTemplateYAML}, "", s.createNucleiTemplate)
	if rec.Code != 201 {
		t.Fatalf("create status = %d: %s", rec.Code, rec.Body.String())
	}
	var created nuclei.TemplateMeta
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID != "custom-api" || created.Source != nuclei.SourceCustom {
		t.Fatalf("created = %+v", created)
	}

	// 详情可编辑
	rec = performJSON(t, s, http.MethodGet, "/api/nuclei/templates/custom-api", nil, "custom-api", s.getNucleiTemplate)
	if rec.Code != 200 {
		t.Fatalf("detail status = %d: %s", rec.Code, rec.Body.String())
	}
	var detail struct {
		Meta     nuclei.TemplateMeta `json:"meta"`
		Content  string              `json:"content"`
		Editable bool                `json:"editable"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if !detail.Editable || detail.Meta.Source != nuclei.SourceCustom {
		t.Fatalf("detail = %+v", detail)
	}

	// 更新
	updatedYAML := testCustomTemplateYAML + "\n"
	rec = performJSON(t, s, http.MethodPut, "/api/nuclei/templates/custom-api", map[string]string{"yaml": updatedYAML}, "custom-api", s.updateNucleiTemplate)
	if rec.Code != 200 {
		t.Fatalf("update status = %d: %s", rec.Code, rec.Body.String())
	}

	// 官方模板不可删
	rec = performJSON(t, s, http.MethodDelete, "/api/nuclei/templates/official-api", nil, "official-api", s.deleteNucleiTemplate)
	if rec.Code != 400 {
		t.Fatalf("official delete status = %d: %s", rec.Code, rec.Body.String())
	}

	// 删除自定义
	rec = performJSON(t, s, http.MethodDelete, "/api/nuclei/templates/custom-api", nil, "custom-api", s.deleteNucleiTemplate)
	if rec.Code != 200 {
		t.Fatalf("delete status = %d: %s", rec.Code, rec.Body.String())
	}
	rec = performJSON(t, s, http.MethodGet, "/api/nuclei/templates/custom-api", nil, "custom-api", s.getNucleiTemplate)
	if rec.Code != 404 {
		t.Fatalf("deleted detail status = %d", rec.Code)
	}
}
