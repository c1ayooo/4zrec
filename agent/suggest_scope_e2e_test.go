package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/c1ayooo/4zrec/acllm"
	"github.com/c1ayooo/4zrec/askernel"
	"github.com/c1ayooo/4zrec/db"
	actool "github.com/c1ayooo/4zrec/tools"
)

// =====================================================================
// suggest_scope 实际有用性测试(真实 LLM)。
//
// "功能能跑"不等于"实际有用":要验证的是真实模型在收尾场景下会不会调
// suggest_scope、提名的质量如何。造景:worker 探索 acme-corp.io 后收尾,
// 页面文本里埋了两个资产库没有的同机构域(acme-cloud.net / acme-labs.cn)
// 和一个子域(sso.acme-corp.io)。期望:调用 suggest_scope、提名至少一个
// 页面独有根域、不把子域/乱串当根域。
// 跳过条件:无 ZREC_LLM_*(或旧名 ARTEX_LLM_*)环境变量(默认 go test ./... 无 key 时零开销)。
// =====================================================================

// recordingHook 借 PreToolUse 观察 suggest_scope 调用(不阻断)。
type recordingHook struct {
	calls []string // 每次 suggest_scope 提名的 domains 展平
}

func (h *recordingHook) PreToolUse(_ context.Context, name string, input json.RawMessage) (bool, string, json.RawMessage) {
	if name == "suggest_scope" {
		var req struct {
			Domains []string `json:"domains"`
		}
		_ = json.Unmarshal(input, &req)
		h.calls = append(h.calls, req.Domains...)
	}
	return false, "", nil
}
func (h *recordingHook) PostToolUse(context.Context, string, json.RawMessage, string, bool) {}
func (h *recordingHook) Stop(context.Context, []acllm.Message) (bool, []string, string) {
	return false, nil, ""
}

func TestSuggestScopeEndToEnd(t *testing.T) {
	cfg, ok := FromEnv()
	if !ok {
		t.Skip("未配置 ZREC_LLM_*(或旧名 ARTEX_LLM_*)环境变量,跳过真实 LLM 实测")
	}
	prov, err := cfg.NewProvider()
	if err != nil {
		t.Skipf("provider 构建失败: %v", err)
	}

	d := testDB(t)
	defer d.Close()

	suffix := time.Now().UnixNano()
	p, err := d.Projects().CreateProject(fmt.Sprintf("LLM建议实测-%d", suffix), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Projects().DeleteProject(p.ID)
	pid := p.ID
	task, err := d.CreateTaskWithOptions("LLM建议实测任务", "探索 acme-corp.io 门户站,识别其资产与子机构", db.TaskCreateOptions{ProjectID: &pid})
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteTask(task.ID)

	// 工具集与 worker 运行时同构的关键子集:suggest_scope(经 db 落库)+
	// list_assets(让模型能先看资产里已有什么)。不给 Bash——只测提名环节。
	ts := NewToolSet(d.Exploration(task.ExplorationID), "worker")
	ts.SetTaskID(task.ID)
	ts.SetAssetStore(d.Assets(), d.Companies())

	// 页面观察:页脚埋两个资产库没有的同机构根域 + 一个子域(SAN 记录)。
	obs := fmt.Sprintf(`探索完成,页面文本摘录:
首页页脚: "Acme Corp © 2025 | Acme Cloud (acme-cloud.net) | Acme Labs (acme-labs.cn) | 官网: acme-corp.io"
证书透明度日志: acme-corp.io 的 SAN 包含 sso.acme-corp.io。
附录: 校验串 %d`, suffix)

	hook := &recordingHook{}
	_, reason, err := captureRun(context.Background(), askernel.Options{
		Model: prov,
		Tools: []actool.CoreTool{ts.suggestScope(), ts.listAssets()},
		// 收尾提示词与 worker 生产语义一致:落库→提名→总结。
		SystemPrompt: []string{"你是渗透测试 worker,负责探索 acme-corp.io。当前进入收尾阶段。"},
		Hooks:        hook,
		MaxTurns:     6,
	}, obs+"\n\n请收尾:把探索中发现的内容落库。", func(db.Activity) {})
	if err != nil {
		t.Skipf("LLM 调用失败(网络/配额): %v, reason=%v", err, reason)
	}

	// 断言 1:模型真的调用了 suggest_scope(有用性的第一问)。
	if len(hook.calls) == 0 {
		t.Fatalf("LLM 未调用 suggest_scope;hook 捕获提名为空")
	}
	// 断言 2:落库可见,且含页面独有的同机构根域(而非只复读资产里已有的)。
	sugs, err := d.ScopeSuggestions(pid)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range sugs {
		got[s["domain"].(string)] = s["reason"].(string)
	}
	hitPage := false
	for _, dm := range hook.calls {
		if dm == "acme-cloud.net" || dm == "acme-labs.cn" {
			hitPage = true
		}
	}
	if !hitPage {
		t.Fatalf("提名 %v 未包含页面独有的同机构域(acme-cloud.net/acme-labs.cn)", hook.calls)
	}
	// 断言 3:提名质量——不收子域,不收空串/乱串。
	for _, dm := range hook.calls {
		if dm == "" || strings.Contains(dm, " ") || dm == "sso.acme-corp.io" {
			t.Fatalf("提名质量差: %q(子域/空串不应入围)", dm)
		}
	}
	t.Logf("✓ LLM 提名 %v;落库 %d 条,依据示例: %q", hook.calls, len(got), firstReason(got))
}

func firstReason(m map[string]string) string {
	for _, v := range m {
		return v
	}
	return ""
}
