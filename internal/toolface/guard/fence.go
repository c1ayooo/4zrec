package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	capguard "github.com/c1ayooo/4zrec/internal/capkit/guard"

	"github.com/c1ayooo/4zrec/internal/domain/db"
	"github.com/c1ayooo/4zrec/internal/kernel/askernel"
	"github.com/c1ayooo/4zrec/internal/toolface/intercept"
)

// =====================================================================
// 资产围栏(执行侧授权闸门)—— 框架层强制,不依赖提示词。
//
// 渗透过程中 agent 可能把命令直接打向「未获授权的目标」(扫描输出里新看到的
// IP/域名,未经 insert_assets 登记、未经人工批准)。本闸门在 guard.PreToolUse
// 这个对话/任务共享的单咽喉上:
//
//  1. 从出网类工具(Bash/shell_open/shell_send/WebFetch/http_probe)的输入提取
//     目标对象(IP/域名/URL host):Bash 走「命令对象」解析,http_probe 按字段
//     结构化取 URL(见 fenceToolTargets/fence_http.go);
//     会话注入的 ZREC_TARGETS(项目授权目标集,见 server/targets_env.go)按
//     「引用即授权」语义工作——`$` 形态 token 本就不产生提取对象(宁漏勿扰),
//     而变量值按构造就是授权集,围栏无需解析;
//  2. 命中全局/任务黑名单 → 硬阻断(平台管控文案);
//  3. 目标已获授权(项目范围命中,或库中 authz='approved' 的资产)→ 放行;
//  4. 其余 → 合成 ask 审批(复用 intercept.HandleAsk:pending 记录 + 内联卡片 +
//     无限等待,与「审批长阻塞」不变量一致);人工批准 → 目标就地登记为
//     approved 资产(批准即授权,后续不再询问)并放行本次调用;拒绝/取消 → 阻断。
//
// 未挂项目的任务/会话不启用围栏(projectID=0),保持旧行为,项目可渐进接入。
// 已知边界:只拦命令文本中字面可见的目标;变量拼接、IPv6、先解析再打等形态
// 不在第一版覆盖内(见 docs/asset-fence)。代码标识符(re.findall/os.path 等)
// 已由 TLD 后缀白名单排除,冷门后缀的真实域名会漏拦(宁漏勿扰,见
// tldAllowlist 注释)。纯十进制三段 IP 变体(1.2.3=1.2.0.3)与版本号碎片同形,
// 刻意不判(suspiciousIPVariant 注释);整数/八进制/十六进制变体已覆盖。
// =====================================================================

// fenceTargets 是一次提取出的目标对象集合。Opaque 表示命令会联网、但静态
// 无法确定其实际对象（解释器脚本、未知命令、不可读的目标列表等）；此时围栏
// 必须走审批，而不是因为「没提取到字面目标」就放行。
type fenceTargets struct {
	Domains []string
	IPs     []string
	Opaque  bool
	Reason  string
}

func (t fenceTargets) empty() bool { return len(t.Domains) == 0 && len(t.IPs) == 0 }

func (t fenceTargets) list() []string {
	out := append([]string(nil), t.Domains...)
	out = append(out, t.IPs...)
	return out
}

// ---- 目标提取已上收 capkit（github.com/c1ayooo/4zrec/internal/capkit/guard，2026-10-24）----
//
// 命令词法、URL 结构化、IP 变体归一、TLD 白名单全部是 capkit/guard 的实现；
// 4zrec 保留的只有 fenceTargets 适配层与 AssetFence 编排（授权判定/审批合成/
// 资产登记——宿主职责）。两仓库从此共享同一套「从哪里提目标」的口径。

// fenceCommandText 按工具取参与提取的文本字段（委托 capkit guard）。
func fenceCommandText(toolName string, input []byte) string {
	// capkit guard.Inspect 内部做同一分派；这里只为审计展示路径保留原签名。
	in := map[string]any{}
	if err := json.Unmarshal(input, &in); err != nil {
		return ""
	}
	str := func(k string) string {
		if v, ok := in[k].(string); ok {
			return v
		}
		return ""
	}
	switch toolName {
	case "Bash", "shell_open":
		return str("command")
	case "shell_send":
		return str("text")
	case "WebFetch":
		return str("url")
	case "http_probe":
		if u := str("url"); u != "" {
			return u
		}
		if reqs, ok := in["requests"].([]any); ok && len(reqs) > 0 {
			if first, ok := reqs[0].(map[string]any); ok {
				if u, ok := first["url"].(string); ok {
					return u
				}
			}
		}
		if tmpl, ok := in["template"].(map[string]any); ok {
			if u, ok := tmpl["url"].(string); ok {
				return u
			}
		}
		return ""
	}
	return ""
}

// fenceToolTargets 按工具提取围栏对象——委托 capkit guard.Inspect（原四个
// 纯逻辑文件已随 2026-10-24 搬迁删除，行为由 capkit 侧同一测试语料钉住）。
func fenceToolTargets(toolName string, input []byte, workDir string) fenceTargets {
	r := capguard.Inspect(toolName, input, workDir)
	return fenceTargets{Domains: r.Domains, IPs: r.IPs, Opaque: r.Opaque, Reason: r.Reason}
}

// IsPublicInfraIP 报告 ip 是否是公共基础设施地址（公共 DNS 解析器等）。
// 表本体已随提取逻辑上收 capkit（guard.IsPublicInfraIP）；空间测绘导入等
// 旁路继续经本别名消费。
func IsPublicInfraIP(ip string) bool {
	return capguard.IsPublicInfraIP(ip)
}

func (t fenceTargets) displayList() string {
	all := t.list()
	if len(all) <= 32 {
		return strings.Join(all, "、")
	}
	return strings.Join(all[:32], "、") + fmt.Sprintf(" 等 %d 个目标", len(all))
}

// AssetFence 是资产围栏的 DB 支撑实现(guard 通过接口持有,便于测试替身)。
type AssetFence struct {
	dbh *db.DB
}

// NewAssetFence 构造围栏;dbh 为nil时围栏不生效。
func NewAssetFence(dbh *db.DB) *AssetFence { return &AssetFence{dbh: dbh} }

// fenceDecision 是一次围栏判定的结果。
type fenceDecision struct {
	ProjectID    int64
	Targets      fenceTargets // 本次提取到的全部目标
	Unauthorized fenceTargets // 其中未获授权的子集(审批/展示/登记只认它)
	Allow        bool         // true=放行(已授权或无目标/无项目)
	HardBlock    bool         // true=命中黑名单,直接阻断
	Opaque       bool         // true=命令联网但对象不可静态确定,必须审批
	Reason       string       // HardBlock 或 Ask 的说明
}

// fenceTargetPayload 是审批记录里持久化的结构化目标(domains/ips 分列,
// 前端按类型渲染复选框,批准时按勾选子集登记授权)。
type fenceTargetPayload struct {
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}

func (t fenceTargets) payload() json.RawMessage {
	raw, _ := json.Marshal(fenceTargetPayload{Domains: t.Domains, IPs: t.IPs})
	return raw
}

// evaluate 执行判定:黑名单 → 未授权(ask) → 放行。
func (f *AssetFence) evaluate(ctx context.Context, toolName string, input []byte) fenceDecision {
	if f == nil || f.dbh == nil {
		return fenceDecision{Allow: true}
	}
	projectID := f.resolveProject(ctx)
	if projectID <= 0 {
		return fenceDecision{Allow: true}
	}
	// 按「对象」解析:Bash 取命令目标操作数;http_probe 按字段结构化取 URL
	// (proxy/headers/body 不参与);解释器/未知命令无法静态确定对象则 Opaque,
	// 交给人工审批——不能因为没提取到字面目标就放行。
	targets := fenceToolTargets(toolName, input, intercept.ReviewWorkingDirectory(ctx))
	if targets.empty() && !targets.Opaque {
		return fenceDecision{Allow: true}
	}
	// 黑名单(全局 ∪ 任务级 block)优先:命中即硬阻断,不给审批机会。
	// Opaque 命令里已识别出的目标也要过黑名单（例如解释器代码里的 .gov 域名）。
	blockRules, _ := f.dbh.ListAssetInterceptRules()
	taskIDStr, _ := intercept.TaskInfoFromContext(ctx)
	if taskID := parseTaskID(taskIDStr); taskID > 0 {
		if tb, _, err := f.dbh.Assets().TaskInterceptRulesSplit(taskID); err == nil {
			blockRules = append(blockRules, tb...)
		}
	}
	if !targets.empty() {
		if rule, val, ok := db.MatchAssetInterceptRules(blockRules, targets.Domains, targets.IPs, nil); ok {
			return fenceDecision{
				ProjectID: projectID, Targets: targets, HardBlock: true,
				Reason: fmt.Sprintf("%s(命中值 %s)", rule.Reason(), val),
			}
		}
	}
	if targets.Opaque {
		return fenceDecision{
			ProjectID: projectID, Targets: targets, Opaque: true,
			Reason: targets.Reason,
		}
	}
	if f.dbh.AuthorizedTarget(projectID, targets.Domains, targets.IPs) {
		return fenceDecision{Allow: true, ProjectID: projectID, Targets: targets}
	}
	// 只把未授权的目标放进审批:文案与登记都用子集——已授权目标不再列进
	// 「不在授权范围内」,批准也不会把范围内目标重复写成资产。
	unauth := f.unauthorized(projectID, targets)
	return fenceDecision{
		ProjectID: projectID, Targets: targets, Unauthorized: unauth,
		Reason: "目标资产不在项目授权范围内：" + unauth.displayList() +
			"。若确属本次委托范围，请批准；否则请拒绝并改测授权内资产。",
	}
}

// unauthorized 逐目标判定授权状态,返回未授权子集(ALL 语义的补集)。
func (f *AssetFence) unauthorized(projectID int64, targets fenceTargets) fenceTargets {
	var out fenceTargets
	for _, dom := range targets.Domains {
		if !f.dbh.AuthorizedTarget(projectID, []string{dom}, nil) {
			out.Domains = append(out.Domains, dom)
		}
	}
	for _, ip := range targets.IPs {
		if !f.dbh.AuthorizedTarget(projectID, nil, []string{ip}) {
			out.IPs = append(out.IPs, ip)
		}
	}
	return out
}

// resolveProject 从上下文解析项目:任务优先,其次会话。
func (f *AssetFence) resolveProject(ctx context.Context) int64 {
	taskIDStr, _ := intercept.TaskInfoFromContext(ctx)
	if taskID := parseTaskID(taskIDStr); taskID > 0 {
		if pid, err := f.dbh.TaskProjectID(taskID); err == nil && pid > 0 {
			return pid
		}
	}
	if convID := intercept.ConvIDFromContext(ctx); convID > 0 {
		if pid, err := f.dbh.ConvProjectID(convID); err == nil && pid > 0 {
			return pid
		}
	}
	return 0
}

func parseTaskID(s string) int64 {
	id, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return id
}

// authorize 在人工批准后把目标就地登记为 approved 资产(批准即授权)。
func (f *AssetFence) authorize(projectID int64, targets fenceTargets) {
	if f == nil || f.dbh == nil || projectID <= 0 {
		return
	}
	for _, dom := range targets.Domains {
		if id, err := f.dbh.EnsureDiscoveredAsset(projectID, "subdomain", dom, ""); err == nil && id > 0 {
			_ = f.dbh.Assets().SetAssetAuthz([]int64{id}, "approved")
		}
	}
	for _, ip := range targets.IPs {
		if id, err := f.dbh.EnsureDiscoveredAsset(projectID, "ip", "", ip); err == nil && id > 0 {
			_ = f.dbh.Assets().SetAssetAuthz([]int64{id}, "approved")
		}
	}
}

// PendingProject 解析一条审批记录的归属项目:任务优先,其次会话;0=无项目。
func (f *AssetFence) PendingProject(p db.InterceptPending) int64 {
	if f == nil || f.dbh == nil {
		return 0
	}
	projectID := int64(0)
	if p.TaskID != nil {
		if tid := parseTaskID(*p.TaskID); tid > 0 {
			projectID, _ = f.dbh.TaskProjectID(tid)
		}
	}
	if projectID <= 0 && p.ConversationID != nil {
		projectID, _ = f.dbh.ConvProjectID(*p.ConversationID)
	}
	return projectID
}

// PendingTargets 返回一条围栏审批的目标清单:优先读记录里的结构化 targets
// (新记录);旧记录没有该列,退回从工具输入重新提取(按全部目标处理)。
func (f *AssetFence) PendingTargets(p db.InterceptPending) (domains, ips []string) {
	if len(p.Targets) > 0 {
		var payload fenceTargetPayload
		if json.Unmarshal(p.Targets, &payload) == nil &&
			(len(payload.Domains) > 0 || len(payload.IPs) > 0) {
			return payload.Domains, payload.IPs
		}
	}
	if !strings.Contains(p.Reason, "【资产围栏】") {
		return nil, nil
	}
	targets := fenceToolTargets(p.ToolName, p.ToolInput, "")
	return targets.Domains, targets.IPs
}

// Authorize 把人工批准的目标登记为 approved 资产(批准即授权)。供审批
// 决定接口按勾选子集调用。
func (f *AssetFence) Authorize(projectID int64, domains, ips []string) {
	f.authorize(projectID, fenceTargets{Domains: domains, IPs: ips})
}

// AskAuthorized 报告一条挂起的审批记录是否已因「资产获批」而可以放行——
// 资产批准联动的谓词(配合 intercept.ReleaseAsks):仅认【资产围栏】消息的
// 记录;从审批记录的归属(任务→项目,会话→项目)解析项目,对工具输入重提
// 目标,全部已获授权(项目范围或 approved 资产)即 true。普通拦截规则的
// ask 不受影响。
func (f *AssetFence) AskAuthorized(p db.InterceptPending) bool {
	if f == nil || f.dbh == nil {
		return false
	}
	if !strings.Contains(p.Reason, "【资产围栏】") {
		return false
	}
	projectID := f.PendingProject(p)
	if projectID <= 0 {
		return false
	}
	targets := fenceToolTargets(p.ToolName, p.ToolInput, "")
	if targets.empty() {
		return false
	}
	return f.dbh.AuthorizedTarget(projectID, targets.Domains, targets.IPs)
}

// applyFence 在工具规则判定之前执行资产围栏。返回值 true 表示已产生终局决定。
func (g *Guard) applyFence(ctx context.Context, ev askernel.Event) (askernel.Result, bool) {
	if g.fence == nil || g.interceptor == nil {
		return askernel.Result{}, false
	}
	d := g.fence.evaluate(ctx, ev.ToolName, ev.Input)
	if d.Allow {
		return askernel.Result{}, false
	}
	if d.HardBlock {
		return g.block(ev.ToolName, systemBlockMessage("目标资产命中拦截规则："+d.Reason), ""), true
	}
	// 未授权 → 合成 ask 审批(无限等待,与「审批长阻塞」不变量一致)。
	// 结构化目标随记录落库:审批页按目标复选(全选/部分),决定接口只把
	// 勾选的目标登记为 approved。
	dec := intercept.Decision{
		Action:  "ask",
		Message: "【资产围栏】" + d.Reason,
		Targets: d.Unauthorized.payload(),
	}
	convID := intercept.ConvIDFromContext(ctx)
	if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
		return g.block(ev.ToolName, systemBlockMessage("目标资产未获项目授权（人工拒绝或工作已取消）"), ""), true
	}
	// 批准后的登记动作在审批决定接口里按勾选子集完成(见 server.interceptDecide);
	// 这里不再无条件把全部目标写成 approved——旧实现会把范围内目标与
	// 未勾选目标一并登记。
	return askernel.Result{}, false
}
