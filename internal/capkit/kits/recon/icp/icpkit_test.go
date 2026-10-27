package icp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math/rand"
	"strings"
	"testing"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// fakeFetcher 按 URL 返回预置响应，模拟 beian 上游。
type fakeFetcher struct {
	responses map[string]string
	calls     []core.Request
}

func (f *fakeFetcher) Fetch(_ context.Context, req core.Request) (*core.Response, error) {
	f.calls = append(f.calls, req)
	body, ok := f.responses[req.URL]
	if !ok {
		body = `{}`
	}
	return &core.Response{Status: 200, Body: []byte(body)}, nil
}

func (f *fakeFetcher) urls() []string {
	out := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		out = append(out, c.URL)
	}
	return out
}

// 默认响应：auth 发 token；验证码图片故意不可解，使客户端退化到兜底 sign；
// queryByCondition 返回一条百度备案记录。
func defaultFetcher() *fakeFetcher {
	return &fakeFetcher{responses: map[string]string{
		authEndpoint:     `{"success":true,"params":{"bussiness":"TOKEN-XYZ","expire":3600000}}`,
		checkImagePoint:  `{"success":true,"params":{"uuid":"u-1","bigImage":"!!!!","smallImage":"!!!!"}}`,
		queryByCondition: `{"success":true,"code":200,"params":{"total":1,"list":[{"unitName":"北京百度网讯科技有限公司","domain":"baidu.com","serviceType":1}]}}`,
	}}
}

func TestManifestValidates(t *testing.T) {
	kit := New(core.Deps{Fetcher: defaultFetcher()})
	reg := core.NewRegistry()
	if err := reg.Add(core.Spec{Manifest: kit.Manifest(), New: NewCapability}); err != nil {
		t.Fatalf("registry.Add: %v", err)
	}
	if err := reg.Validate(core.Deps{Fetcher: defaultFetcher()}); err != nil {
		t.Fatalf("registry.Validate: %v", err)
	}
	tools := kit.Manifest().Tools
	if len(tools) != 2 {
		t.Fatalf("want 2 tools, got %d", len(tools))
	}
	for _, tool := range tools {
		if tool.ExtractTargets == nil {
			t.Errorf("tool %s: ExtractTargets 必须显式声明为非 nil（返回空）", tool.Name)
		}
		if tg, err := tool.ExtractTargets(nil); err != nil || tg != nil {
			t.Errorf("tool %s: 非目标工具应返回 (nil,nil)，得到 (%v,%v)", tool.Name, tg, err)
		}
	}
}

func TestNewCapabilityRequiresFetcher(t *testing.T) {
	if _, err := NewCapability(core.Deps{}); err == nil {
		t.Fatal("缺少 fetcher 时 NewCapability 应报错")
	}
}

func TestQueryWeb(t *testing.T) {
	ff := defaultFetcher()
	kit := New(core.Deps{Fetcher: ff})
	res, err := kit.Call(context.Background(), core.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"baidu.com","type":"web"}`),
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if !res.OK {
		t.Fatalf("查询失败: %+v", res.Error)
	}
	var out map[string]any
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("解析结果: %v", err)
	}
	if out["type"] != "web" || out["count"] != float64(1) {
		t.Fatalf("非预期结果: %s", res.Data)
	}
	// 必须经过 auth -> (验证码失败) -> 兜底 sign -> queryByCondition。
	urls := strings.Join(ff.urls(), "\n")
	for _, want := range []string{authEndpoint, checkImagePoint, queryByCondition} {
		if !strings.Contains(urls, want) {
			t.Errorf("未调用 %s，实际: %v", want, ff.urls())
		}
	}
}

func TestQueryBlacklistDomain(t *testing.T) {
	ff := defaultFetcher()
	ff.responses[blackByCondition] = `{"success":true,"code":200,"params":{"list":[{"domain":"evil.com"}]}}`
	kit := New(core.Deps{Fetcher: ff})
	res, err := kit.Call(context.Background(), core.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"evil.com","type":"bweb"}`),
	})
	if err != nil || !res.OK {
		t.Fatalf("黑名单查询失败: err=%v res=%+v", err, res)
	}
	if !strings.Contains(strings.Join(ff.urls(), "\n"), blackByCondition) {
		t.Fatalf("未命中黑名单端点: %v", ff.urls())
	}
}

func TestAppDetailFanout(t *testing.T) {
	ff := defaultFetcher()
	ff.responses[queryByCondition] = `{"success":true,"code":200,"params":{"list":[
		{"dataId":1001,"serviceType":6},
		{"dataId":1002,"serviceType":6}
	]}}`
	ff.responses[appDetailEndpoint] = `{"success":true,"params":{"dataId":1001,"domain":"detail.example","appName":"X"}}`
	kit := New(core.Deps{Fetcher: ff})
	res, err := kit.Call(context.Background(), core.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"某App","type":"app"}`),
	})
	if err != nil || !res.OK {
		t.Fatalf("App 查询失败: err=%v res=%+v", err, res)
	}
	var out struct {
		Result struct {
			Params struct {
				List []map[string]any `json:"list"`
			} `json:"params"`
		} `json:"result"`
	}
	if err := json.Unmarshal(res.Data, &out); err != nil {
		t.Fatalf("解析: %v", err)
	}
	if len(out.Result.Params.List) != 2 {
		t.Fatalf("期望 2 条，得到 %d", len(out.Result.Params.List))
	}
	if out.Result.Params.List[0]["domain"] != "detail.example" {
		t.Errorf("首条未替换为详情: %v", out.Result.Params.List[0])
	}
}

func TestRejectsUnsupportedType(t *testing.T) {
	kit := New(core.Deps{Fetcher: defaultFetcher()})
	res, _ := kit.Call(context.Background(), core.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"x","type":"nope"}`),
	})
	if res.OK || res.Error == nil || res.Error.Code != core.CodeInvalidInput {
		t.Fatalf("非法类型应报 invalid_input: %+v", res)
	}
}

func TestTypesTool(t *testing.T) {
	kit := New(core.Deps{Fetcher: defaultFetcher()})
	res, err := kit.Call(context.Background(), core.Call{Tool: "icp_types"})
	if err != nil || !res.OK {
		t.Fatalf("icp_types 失败: err=%v res=%+v", err, res)
	}
	if !strings.Contains(string(res.Data), `"bweb"`) {
		t.Fatalf("类型目录缺少 bweb: %s", res.Data)
	}
}

func TestWAFBlockSurfacesError(t *testing.T) {
	ff := defaultFetcher()
	ff.responses[authEndpoint] = `<html>当前访问疑似黑客攻击</html>`
	kit := New(core.Deps{Fetcher: ff})
	res, _ := kit.Call(context.Background(), core.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"baidu.com"}`),
	})
	if res.OK || res.Error == nil || !strings.Contains(res.Error.Message, "创宇盾") {
		t.Fatalf("应识别创宇盾拦截: %+v", res)
	}
}

// ---- 输出契约：Summary 与信封 ----

// TestQuerySummarySuccess 成功路径：Summary 必须点名目标、动作与关键结果，
// Meta.Tool 必须等于工具名，且处于六态之内。
func TestQuerySummarySuccess(t *testing.T) {
	kit := New(core.Deps{Fetcher: defaultFetcher()})
	res, err := kit.Call(context.Background(), core.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"baidu.com"}`),
	})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if res.Status != core.StatusSuccess || !res.OK {
		t.Fatalf("status=%s ok=%v", res.Status, res.OK)
	}
	if res.Meta.Tool != "icp_query" || res.Meta.Version != kitVersion {
		t.Fatalf("meta = %+v", res.Meta)
	}
	for _, want := range []string{"baidu.com", "主办单位", "北京百度网讯科技有限公司"} {
		if !strings.Contains(res.Summary, want) {
			t.Errorf("Summary %q 缺少 %q", res.Summary, want)
		}
	}
	if len([]rune(res.Summary)) > core.MaxSummaryRunes {
		t.Errorf("Summary 超过 %d rune: %q", core.MaxSummaryRunes, res.Summary)
	}
}

// TestQuerySummaryWithLicence 结果含备案号时，Summary 应带出主办单位与备案号。
func TestQuerySummaryWithLicence(t *testing.T) {
	ff := defaultFetcher()
	ff.responses[queryByCondition] = `{"success":true,"code":200,"params":{"list":[
		{"unitName":"某某科技有限公司","serviceLicence":"京ICP备00000000号-1"}
	]}}`
	kit := New(core.Deps{Fetcher: ff})
	res, _ := kit.Call(context.Background(), core.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"example.com"}`),
	})
	want := "查询 example.com 的 ICP 备案：主办单位 某某科技有限公司，备案号 京ICP备00000000号-1"
	if res.Summary != want {
		t.Fatalf("Summary = %q, want %q", res.Summary, want)
	}
}

// TestQuerySummaryEmpty 空结果：Summary 必须明说未查到，而不是空白或泛化短语。
func TestQuerySummaryEmpty(t *testing.T) {
	ff := defaultFetcher()
	ff.responses[queryByCondition] = `{"success":true,"code":200,"params":{"total":0,"list":[]}}`
	kit := New(core.Deps{Fetcher: ff})
	res, _ := kit.Call(context.Background(), core.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"nonexistent.example"}`),
	})
	if !res.OK {
		t.Fatalf("空结果仍应是成功信封: %+v", res)
	}
	if res.Summary != "nonexistent.example 未查到备案" {
		t.Fatalf("Summary = %q", res.Summary)
	}
	if res.Meta.Tool != "icp_query" {
		t.Fatalf("Meta.Tool = %q", res.Meta.Tool)
	}
}

// TestTypesSummary icp_types 的 Summary 必须说明实际返回了多少种类型。
func TestTypesSummary(t *testing.T) {
	kit := New(core.Deps{Fetcher: defaultFetcher()})
	res, err := kit.Call(context.Background(), core.Call{Tool: "icp_types"})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	want := fmt.Sprintf("返回 %d 种 ICP 主体类型", len(TypeCatalog()))
	if res.Status != core.StatusSuccess || res.Summary != want {
		t.Fatalf("status=%s summary=%q want %q", res.Status, res.Summary, want)
	}
	if res.Meta.Tool != "icp_types" {
		t.Fatalf("Meta.Tool = %q", res.Meta.Tool)
	}
}

// TestUnavailableSummary 不可用路径：创宇盾拦截必须落成 unavailable，且带可读
// Summary 与固定枚举内的 Error.Code。
func TestUnavailableSummary(t *testing.T) {
	ff := defaultFetcher()
	ff.responses[authEndpoint] = `<html>当前访问疑似黑客攻击</html>`
	kit := New(core.Deps{Fetcher: ff})
	res, _ := kit.Call(context.Background(), core.Call{
		Tool:  "icp_query",
		Input: json.RawMessage(`{"query":"baidu.com"}`),
	})
	if res.Status != core.StatusUnavailable || res.OK {
		t.Fatalf("status=%s ok=%v", res.Status, res.OK)
	}
	if res.Error == nil || res.Error.Code != core.CodeUnavailable {
		t.Fatalf("error = %+v", res.Error)
	}
	if strings.TrimSpace(res.Summary) == "" {
		t.Fatalf("unavailable 路径 Summary 不得为空")
	}
	if res.Meta.Tool != "icp_query" {
		t.Fatalf("Meta.Tool = %q", res.Meta.Tool)
	}
}

// TestUnknownToolEnvelope 未知工具：信封仍须完整（Status/Meta.Summary）。
func TestUnknownToolEnvelope(t *testing.T) {
	kit := New(core.Deps{Fetcher: defaultFetcher()})
	res, _ := kit.Call(context.Background(), core.Call{Tool: "nope"})
	if res.Status != core.StatusFailed || res.Error == nil || res.Error.Code != core.CodeNotFound {
		t.Fatalf("未知工具应报 not_found: %+v", res)
	}
	if res.Meta.Tool != "nope" || strings.TrimSpace(res.Summary) == "" {
		t.Fatalf("未知工具信封不完整: %+v", res)
	}
}

// ---- 滑块缺口定位 ----

// makePNG 编码一张 PNG 并返回 base64（与上游验证码字段一致）。
func makePNG(t *testing.T, img image.Image) string {
	t.Helper()
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png.Encode: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// TestMatchSliderOffset 构造噪声背景 + 纯色缺口方块，验证定位到原始 x 偏移。
func TestMatchSliderOffset(t *testing.T) {
	const bw, bh = 300, 150
	const gapX0, gapY0, gapSide = 100, 40, 50

	big := image.NewRGBA(image.Rect(0, 0, bw, bh))
	rng := rand.New(rand.NewSource(7))
	for y := 0; y < bh; y++ {
		for x := 0; x < bw; x++ {
			big.Set(x, y, color.RGBA{uint8(rng.Intn(256)), uint8(rng.Intn(256)), uint8(rng.Intn(256)), 255})
		}
	}
	gapColor := color.RGBA{200, 20, 20, 255}
	for y := gapY0; y < gapY0+gapSide; y++ {
		for x := gapX0; x < gapX0+gapSide; x++ {
			big.Set(x, y, gapColor)
		}
	}
	small := image.NewRGBA(image.Rect(0, 0, gapSide, gapSide))

	got, err := matchSliderOffset(makePNG(t, small), makePNG(t, big))
	if err != nil {
		t.Fatalf("matchSliderOffset: %v", err)
	}
	if got != gapX0 {
		t.Fatalf("缺口 x 期望 %d，得到 %d", gapX0, got)
	}
}
