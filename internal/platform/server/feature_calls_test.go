package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/orchestration/agent"
	actool "github.com/c1ayooo/4zrec/internal/toolface/tools"
)

type featureCallSink struct {
	calls []db.FeatureCall
}

func (s *featureCallSink) InsertFeatureCall(c *db.FeatureCall) error {
	s.calls = append(s.calls, *c)
	return nil
}

func TestFeatureToolSpecMapping(t *testing.T) {
	cases := map[string]struct{ feature, action string }{
		"search_vuln_kb":         {FeatureVulnKB, "lookup"},
		"nuclei_scan":            {FeatureNuclei, "scan"},
		"nuclei_template_search": {FeatureNuclei, "template_search"},
		"nuclei_update":          {FeatureNuclei, "update"},
		"fingerprint_scan":       {FeatureFingerprint, "scan"},
	}
	for key, want := range cases {
		spec := featureToolSpecFor(key)
		if spec == nil || spec.Feature != want.feature || spec.Action != want.action {
			t.Errorf("%s: got %+v, want %s/%s", key, spec, want.feature, want.action)
		}
	}
	if featureToolSpecFor("nuclei_status") != nil {
		t.Error("nuclei_status should not be recorded")
	}
}

func TestFeatureCallSummaries(t *testing.T) {
	t.Run("vulnkb search", func(t *testing.T) {
		query, summary := summarizeVulnKBSearch(
			json.RawMessage(`{"q":"泛微"}`),
			actool.Text("命中 5 条（库内），展示前 5 条：\n"),
		)
		if query != "泛微" || summary != "查询「泛微」命中 5 条" {
			t.Fatalf("query=%q summary=%q", query, summary)
		}
	})
	t.Run("nuclei scan", func(t *testing.T) {
		query, summary := summarizeNucleiScan(
			json.RawMessage(`{"targets":["https://a.example","https://b.example"]}`),
			actool.Text("nuclei 扫描完成：2 命中 / 2 目标 / 18 模板，耗时 4.2s\n"),
		)
		if query != "https://a.example, https://b.example" {
			t.Fatalf("query=%q", query)
		}
		if summary != "扫描 2 个目标，命中 2 条（18 模板，耗时 4.2s）" {
			t.Fatalf("summary=%q", summary)
		}
	})
	t.Run("fingerprint scan", func(t *testing.T) {
		_, summary := summarizeFingerprintScan(
			json.RawMessage(`{"targets":["https://a.example"]}`),
			actool.Text("扫描 1 目标,规则命中 3 条;组件结论已回写服务资产\n"),
		)
		if summary != "扫描 1 个目标，规则命中 3 条" {
			t.Fatalf("summary=%q", summary)
		}
	})
}

func TestParseFeatureCallTime(t *testing.T) {
	for _, raw := range []string{"", "2026-10-18T12:00:00Z", "2026-10-18T12:00:00", "2026-10-18"} {
		if _, ok := parseFeatureCallTime(raw); !ok {
			t.Errorf("%q should parse", raw)
		}
	}
	if _, ok := parseFeatureCallTime("not-a-time"); ok {
		t.Error("invalid time should fail")
	}
}

func TestTruncateFeatureJSON(t *testing.T) {
	small := json.RawMessage(`{"a":1}`)
	if got := string(truncateFeatureJSON(small, 100)); got != string(small) {
		t.Fatalf("small json changed: %s", got)
	}
	large := json.RawMessage(`{"a":"` + strings.Repeat("x", 200) + `"}`)
	got := truncateFeatureJSON(large, 50)
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("truncated json invalid: %v (%s)", err, got)
	}
	if m["truncated"] != true {
		t.Fatalf("truncated marker missing: %s", got)
	}
}

func TestRecordMeteredFeatureCall(t *testing.T) {
	sink := &featureCallSink{}
	ri := agent.RunInfo{TaskID: 42, ExplorationID: 8, IntentID: 9, SessionID: "session-1"}
	recordMeteredFeatureCall(
		sink,
		featureToolSpecFor("search_vuln_kb"),
		"planner",
		ri,
		json.RawMessage(`{"q":"泛微","project_id":7}`),
		actool.Text("命中 5 条（库内）"),
		nil,
		30*time.Millisecond,
	)
	if len(sink.calls) != 1 {
		t.Fatalf("calls=%d", len(sink.calls))
	}
	c := sink.calls[0]
	if c.Feature != FeatureVulnKB || c.Action != "lookup" || c.Source != "agent" || c.Status != "ok" {
		t.Fatalf("unexpected call: %+v", c)
	}
	if c.Actor != "planner" || c.TaskID != 42 || c.ExplorationID != 8 || c.IntentID != 9 ||
		c.SessionID != "session-1" || c.ProjectID != 7 {
		t.Fatalf("attribution: %+v", c)
	}
	if c.Query != "泛微" || !strings.Contains(c.Summary, "5 条") || c.DurationMS != 30 {
		t.Fatalf("summary fields: %+v", c)
	}

	recordMeteredFeatureCall(
		sink,
		featureToolSpecFor("fingerprint_scan"),
		"recon",
		ri,
		json.RawMessage(`{"targets":["https://a.example"]}`),
		actool.Errorf("目标越界"),
		nil,
		time.Second,
	)
	if len(sink.calls) != 2 {
		t.Fatalf("calls=%d", len(sink.calls))
	}
	if sink.calls[1].Status != "error" || sink.calls[1].Error != "目标越界" {
		t.Fatalf("error call: %+v", sink.calls[1])
	}
}
