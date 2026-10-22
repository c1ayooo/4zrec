package server

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/cloudwego/eino/components/model"
	"github.com/cloudwego/eino/schema"

	"github.com/c1ayooo/4zrec/internal/capability/recon/fingerprint"
	"github.com/c1ayooo/4zrec/internal/capability/vuln/vulnintel"
	"github.com/c1ayooo/4zrec/internal/platform/notify"
)

// wireVulnPipeline 把情报分析流水线接进宿主,注入三个钩子:
//   - LLM:与报告子系统同构 —— 取激活 profile 的 provider,低温有界输出,
//     LLM 调用自动进入 llmrec 录制(providerForProfile 里已包 llmrec.Wrap);
//   - 模板落盘:走 nuclei 自定义模板目录(带 info.author 校验,复用热加载);
//   - 指纹落库:写 fingerprint_rules(source=custom),确认后即时生效;
//   - 高危情报通知:转成一条汇总 IM 推送。
//
// 都允许缺失:缺 LLM 时分析流水线静默跳过(与 report 缺席时降级一致),缺模板
// 库/指纹库时仅不能自动生成对应产物。
func (s *Server) wireVulnPipeline() {
	m := s.m
	if m == nil || m.vulnIntel == nil {
		return
	}
	m.vulnIntel.SetLLM(vulnintel.LLM{
		Complete: s.vulnPipelineComplete,
		Model:    s.vulnPipelineModel,
	})
	m.vulnIntel.SetTemplateSink(s.saveIntelNucleiTemplate)
	m.vulnIntel.SetFingerprintSink(s.saveIntelFingerprintRule)
	m.vulnIntel.SetNotifyHook(s.notifyVulnIntel)
}

// vulnPipelineComplete 是注入给分析层的单次补全:激活 LLM profile + 低温有界。
func (s *Server) vulnPipelineComplete(ctx context.Context, system, user string, maxTokens int) (string, error) {
	p, err := s.m.PG().ActiveProfile()
	if err != nil || p == nil {
		return "", errReportNoProfile
	}
	prov, _, ok := s.providerForProfile(p.ID)
	if !ok {
		return "", errReportNoProfile
	}
	msg, err := prov.Generate(ctx,
		[]*schema.Message{schema.SystemMessage(system), schema.UserMessage(user)},
		model.WithMaxTokens(maxTokens),
		model.WithTemperature(0),
	)
	if err != nil {
		return "", err
	}
	return msg.Content, nil
}

// vulnPipelineModel 返回当前激活配置的模型名,仅用于在分析产物里标注来源。
func (s *Server) vulnPipelineModel() string {
	p, err := s.m.PG().ActiveProfile()
	if err != nil || p == nil {
		return ""
	}
	if m := strings.TrimSpace(p.Model); m != "" {
		return m
	}
	return strings.TrimSpace(p.Name)
}

// saveIntelNucleiTemplate 把情报生成的模板写进项目自定义模板库
// (data/nuclei/custom-templates/<id>.yaml)。overwrite=true:重新分析应覆盖
// 上一版,而不是撞「已存在」报错。
func (s *Server) saveIntelNucleiTemplate(id, yamlText string) error {
	mgr := s.nucleiManager()
	if _, err := mgr.ValidateCustomTemplate(yamlText); err != nil {
		return err
	}
	_, err := mgr.SaveCustomTemplate(yamlText, true)
	return err
}

// saveIntelFingerprintRule 把人工确认的指纹草稿写进统一指纹规则库。规则来源
// 标记为 custom —— 上游 24h 同步不会删除 custom 规则;写入后立即失效匹配缓存,
// 下一次 fingerprint_scan 就能用上。
func (s *Server) saveIntelFingerprintRule(name, category, expression string) (string, error) {
	pg := s.m.PG()
	if pg == nil {
		return "", fmt.Errorf("数据库不可用")
	}
	store, err := fingerprint.NewStore(pg.DB)
	if err != nil {
		return "", err
	}
	id, err := store.SaveCustomRule(context.Background(), name, category, expression)
	if err != nil {
		return "", err
	}
	fingerprint.CacheInvalidate()
	return id, nil
}

// notifyVulnIntel 把一轮新增的高危/严重情报汇成一条 IM 推送。情报不是 finding,
// 没有 task/finding id,因此 finding_id 传 0,靠 title/summary 承载内容。
func (s *Server) notifyVulnIntel(newHigh int, titles []string) {
	if newHigh <= 0 {
		return
	}
	summary := strings.Join(titles, "\n")
	const maxTitles = 8
	if len(titles) > maxTitles {
		summary = fmt.Sprintf("%s\n(其余 %d 条略)", strings.Join(titles[:maxTitles], "\n"), len(titles)-maxTitles)
	}
	if _, err := s.m.pg.AddNotificationEvent(context.Background(), notify.EventVulnIntelNew, 0,
		notify.Snapshot{
			Kind:      notify.EventVulnIntelNew,
			Title:     "漏洞情报：新增高危/严重通告",
			Category:  "漏洞",
			Severity:  "high",
			Summary:   summary,
			ActionURL: "/function/vuln-kb",
		}); err != nil {
		log.Printf("[vulnintel] 高危情报通知写入失败: %v", err)
	}
}

// putPipelineSettings 写入五个开关。都是 settings 键,即时生效(分析 worker 每轮
// 重新读取),无需重启。
func (s *Server) putPipelineSettings(req map[string]any) error {
	pairs := []struct {
		key  string
		name string
	}{
		{"analyze_enabled", "analyze_enabled"},
		{"auto_translate", "auto_translate"},
		{"auto_nuclei", "auto_nuclei"},
		{"auto_fingerprint", "auto_fingerprint"},
		{"notify_enabled", "notify_enabled"},
	}
	for _, p := range pairs {
		v, ok := req[p.name]
		if !ok {
			continue
		}
		b, ok := v.(bool)
		if !ok {
			continue
		}
		if err := s.m.pg.SetBool(vulnPipelineSettingKey(p.key), b); err != nil {
			return err
		}
	}
	return nil
}

// vulnPipelineSettingKey 是流水线开关的 settings 键(与 vulnintel 包内的常量
// 保持一致;包内常量不导出,这里显式列名以免两侧漂移)。
func vulnPipelineSettingKey(name string) string {
	return "vulnintel." + name
}
