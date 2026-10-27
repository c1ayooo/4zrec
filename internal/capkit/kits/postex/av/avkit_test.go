package av

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

type fakeSession struct {
	os    string
	out   map[string]core.Output
	calls []string
}

func (f *fakeSession) Exec(_ context.Context, cmd string, _ core.ExecOpts) (core.Output, error) {
	f.calls = append(f.calls, cmd)
	for k, v := range f.out {
		if strings.Contains(cmd, k) {
			v.Command = cmd
			return v, nil
		}
	}
	return core.Output{Command: cmd}, nil
}
func (f *fakeSession) Info() core.SessionInfo {
	return core.SessionInfo{ID: "s1", OS: f.os, Host: "10.0.0.9"}
}
func (f *fakeSession) Close() error { return nil }

type fakeManager struct{ sess core.Session }

func (m *fakeManager) Open(context.Context, core.SessionSpec) (core.SessionInfo, error) {
	return core.SessionInfo{}, nil
}
func (m *fakeManager) Get(string) (core.Session, bool) {
	if m.sess == nil {
		return nil, false
	}
	return m.sess, true
}
func (m *fakeManager) List() []core.SessionInfo { return nil }
func (m *fakeManager) Close(string) error       { return nil }

func newCap(t *testing.T, s core.Session) *Capability {
	t.Helper()
	c, err := NewCapability(core.Deps{Sessions: &fakeManager{sess: s}})
	if err != nil {
		t.Fatal(err)
	}
	return c.(*Capability)
}

func call(t *testing.T, c *Capability, tool string, in any) core.Result {
	t.Helper()
	raw, _ := json.Marshal(in)
	res, err := c.Call(context.Background(), core.Call{Tool: tool, Input: raw})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestManifestSchemas(t *testing.T) {
	m := Manifest()
	if len(m.Tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(m.Tools))
	}
	for _, spec := range m.Tools {
		if len(spec.InputSchema) == 0 || !json.Valid(spec.InputSchema) {
			t.Errorf("%s: bad InputSchema", spec.Name)
		}
		if len(spec.OutputSchema) == 0 || !json.Valid(spec.OutputSchema) {
			t.Errorf("%s: bad OutputSchema", spec.Name)
		}
		if !spec.Risk.Valid() {
			t.Errorf("%s: bad risk", spec.Name)
		}
	}
}

func TestDatabaseWellFormed(t *testing.T) {
	db := DefaultDatabase()
	if len(db.Products) < 10 {
		t.Fatalf("database too small: %d", len(db.Products))
	}
	seen := map[string]bool{}
	for _, p := range db.Products {
		if p.ID == "" || p.Name == "" || p.Vendor == "" {
			t.Errorf("product missing identity: %+v", p)
		}
		if seen[p.ID] {
			t.Errorf("duplicate product id %q", p.ID)
		}
		seen[p.ID] = true
		if p.Platform != "linux" && p.Platform != "windows" {
			t.Errorf("%s: bad platform %q", p.ID, p.Platform)
		}
		if len(p.Processes)+len(p.Services)+len(p.Drivers)+len(p.Registry)+len(p.Files) == 0 {
			t.Errorf("%s: has no signatures", p.ID)
		}
		if p.Notes == "" {
			t.Errorf("%s: missing notes", p.ID)
		}
	}
}

func TestDetectWindowsDefender(t *testing.T) {
	sess := &fakeSession{os: "windows", out: map[string]core.Output{
		"tasklist":    {Stdout: "MsMpEng.exe,1234,Console,1,100 K\n"},
		"sc query":    {Stdout: "SERVICE_NAME: WinDefend\nSERVICE_NAME: Sysmon64\n"},
		"driverquery": {Stdout: "WdFilter.sys\n"},
	}}
	c := newCap(t, sess)
	res := call(t, c, "av_detect", map[string]any{"session_id": "s1"})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s err=%+v", res.Status, res.Error)
	}
	var data struct {
		Platform   string      `json:"platform"`
		Count      int         `json:"count"`
		Detections []Detection `json:"detections"`
	}
	if err := json.Unmarshal(res.Data, &data); err != nil {
		t.Fatal(err)
	}
	if data.Platform != "windows" {
		t.Fatalf("platform=%s", data.Platform)
	}
	ids := map[string]bool{}
	for _, d := range data.Detections {
		ids[d.ProductID] = true
	}
	if !ids["ms-defender"] {
		t.Errorf("defender not detected: %+v", data.Detections)
	}
	if !ids["sysmon"] {
		t.Errorf("sysmon not detected: %+v", data.Detections)
	}
	if len(res.Findings) == 0 {
		t.Error("expected findings")
	}
}

func TestDetectLinuxFalco(t *testing.T) {
	sess := &fakeSession{os: "linux", out: map[string]core.Output{
		"ps -eo comm=": {Stdout: "falco\nsystemd\n"},
		"lsmod":        {Stdout: "falco 1234 0\n"},
		"dpkg -l":      {Stdout: "ii falco 0.37.1\n"},
	}}
	c := newCap(t, sess)
	res := call(t, c, "av_detect", map[string]any{"session_id": "s1"})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s", res.Status)
	}
	var data struct {
		Detections []Detection `json:"detections"`
	}
	_ = json.Unmarshal(res.Data, &data)
	found := false
	for _, d := range data.Detections {
		if d.ProductID == "falco" {
			found = true
			if len(d.Matches) == 0 {
				t.Error("falco detected with no matches")
			}
		}
	}
	if !found {
		t.Fatalf("falco not detected: %+v", data.Detections)
	}
}

func TestDetectCategoryFilter(t *testing.T) {
	sess := &fakeSession{os: "windows", out: map[string]core.Output{
		"tasklist":    {Stdout: "MsMpEng.exe\nSysmon64.exe\n"},
		"sc query":    {Stdout: "SERVICE_NAME: Sysmon64\n"},
		"driverquery": {Stdout: "SysmonDrv.sys\n"},
	}}
	c := newCap(t, sess)
	res := call(t, c, "av_detect", map[string]any{"session_id": "s1", "category": "logging"})
	var data struct {
		Detections []Detection `json:"detections"`
	}
	_ = json.Unmarshal(res.Data, &data)
	for _, d := range data.Detections {
		if d.Category != CatLogging {
			t.Errorf("category filter leaked %s (%s)", d.ProductID, d.Category)
		}
	}
}

func TestDetectNoMatches(t *testing.T) {
	sess := &fakeSession{os: "linux", out: map[string]core.Output{
		"ps -eo comm=": {Stdout: "nginx\nsshd\n"},
	}}
	c := newCap(t, sess)
	res := call(t, c, "av_detect", map[string]any{"session_id": "s1"})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s", res.Status)
	}
	var data struct {
		Count int `json:"count"`
	}
	_ = json.Unmarshal(res.Data, &data)
	if data.Count != 0 {
		t.Fatalf("expected 0 detections, got %d", data.Count)
	}
	if !strings.Contains(res.Summary, "未") {
		t.Errorf("summary should say nothing found: %s", res.Summary)
	}
}

func TestDetectMissingManager(t *testing.T) {
	c, _ := NewCapability(core.Deps{})
	res, _ := c.(*Capability).Call(context.Background(), core.Call{Tool: "av_detect", Input: json.RawMessage(`{"session_id":"x"}`)})
	if res.Status != core.StatusUnavailable || res.Error.Code != core.CodeToolMissing {
		t.Fatalf("status=%s err=%+v", res.Status, res.Error)
	}
}

func TestDetectSessionNotFound(t *testing.T) {
	c, _ := NewCapability(core.Deps{Sessions: &fakeManager{}})
	res, _ := c.(*Capability).Call(context.Background(), core.Call{Tool: "av_detect", Input: json.RawMessage(`{"session_id":"missing"}`)})
	if res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("%+v", res.Error)
	}
}

func TestUnknownTool(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	res := call(t, c, "av_bogus", map[string]any{})
	if res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("%+v", res.Error)
	}
}

func TestListAll(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	res := call(t, c, "av_list", map[string]any{})
	if res.Status != core.StatusSuccess {
		t.Fatalf("status=%s", res.Status)
	}
	var data struct {
		Count    int `json:"count"`
		Products []struct {
			ID       string `json:"id"`
			Category string `json:"category"`
		} `json:"products"`
	}
	_ = json.Unmarshal(res.Data, &data)
	if data.Count != len(DefaultDatabase().Products) {
		t.Fatalf("list count %d != db size %d", data.Count, len(DefaultDatabase().Products))
	}
}

func TestListCategoryFilterDoesNotMutateDB(t *testing.T) {
	c := newCap(t, &fakeSession{os: "linux"})
	before := len(DefaultDatabase().Products)
	_ = call(t, c, "av_list", map[string]any{"category": "edr"})
	after := len(DefaultDatabase().Products)
	if before != after {
		t.Fatalf("list mutated the DB: %d -> %d", before, after)
	}
	var data struct {
		Products []struct {
			Category string `json:"category"`
		} `json:"products"`
	}
	res := call(t, c, "av_list", map[string]any{"category": "edr"})
	_ = json.Unmarshal(res.Data, &data)
	for _, p := range data.Products {
		if p.Category != string(CatEDR) {
			t.Fatalf("filter leaked category %q", p.Category)
		}
	}
}

func TestDetectPlatformProbe(t *testing.T) {
	sess := &fakeSession{os: "", out: map[string]core.Output{"uname -s": {Stdout: "Linux\n"}}}
	c := newCap(t, sess)
	if got := detectPlatform(context.Background(), c, sess, 0); got != "linux" {
		t.Fatalf("got %q", got)
	}
}

func TestMatchListAndSample(t *testing.T) {
	got := matchList("hello world defender here", "hello world defender here", []string{"defender"}, "process")
	if len(got) != 1 || got[0].Kind != "process" || got[0].Value != "defender" {
		t.Fatalf("%+v", got)
	}
	if matchList("nothing", "nothing", nil, "process") != nil {
		t.Fatal("nil needles should yield nil")
	}
}
