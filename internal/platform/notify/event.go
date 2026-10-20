package notify

import "strings"

// Snapshot 是 notification_events.snapshot 这一 JSONB 列的契约。写方是 db 层/
// server 层的事件生产者，读方是投递引擎与过滤匹配。定义放在本包是因为它是
// 「通知领域」的载荷：db 只负责序列化，不理解字段含义。
//
// 为什么冗余存当时的字段而不在渲染时回查：漏洞事后会被改名、改级别、改状态，
// 而推送内容应当反映**事发当时**的结论——回查会得到「事后被改成 low」的
// 危险误导。另外 fan-out 与渲染因此不必 JOIN findings/tasks/assets 三张表。
type Snapshot struct {
	// Kind 是事件类型，取值见 Event* 常量。
	Kind      string `json:"kind"`
	FindingID int64  `json:"finding_id"`
	TaskID    int64  `json:"task_id"`
	ProjectID int64  `json:"project_id,omitempty"`
	VulnClass string `json:"vulnclass,omitempty"`
	Name      string `json:"name,omitempty"`
	// Title 是通用事件的展示标题；漏洞事件仍用 Name/VulnClass。
	Title    string  `json:"title,omitempty"`
	Category string  `json:"category,omitempty"`
	Severity string  `json:"severity"`
	Summary  string  `json:"summary"`
	AssetIDs []int64 `json:"asset_ids,omitempty"`
	// ActionURL 是通用事件的回链（相对路径会拼上 public_base_url）。
	ActionURL string `json:"action_url,omitempty"`
	// 仅 kind=finding_status_changed 时非空。
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
}

// Item 是一条待推送条目，供渠道渲染。
type Item struct {
	Kind      string
	Category  string
	FindingID int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string
	// Assets 是解析后的资产展示名（如域名/IP）。由 server 层填充——
	// 本包不碰数据库，拿不到名字。
	Assets []string
	// DetailURL 是详情/操作回链；为空表示未配 public_base_url，渲染时省略。
	DetailURL string
	// 状态变更事件专用；两项均非空时渲染成「待处理 → 已修复」。
	FromStatus string
	ToStatus   string
}

// IsStatusChange 报告该条目是否为状态变更事件。
func (i Item) IsStatusChange() bool { return i.FromStatus != "" || i.ToStatus != "" }

// IsFinding 报告该条目是否属于漏洞域。空 Kind 是旧库兼容（历史快照只有漏洞）。
func (i Item) IsFinding() bool {
	switch i.Kind {
	case "", EventFindingCreated, EventFindingStatusChanged, EventFindingRetestReproduced:
		return true
	}
	return false
}

// Title 返回条目的展示标题：优先人工命名的 name，回退漏洞类型 vulnclass，
// 两者都空时用一个占位符——绝不输出空标题。
func (i Item) Title() string {
	if i.Name != "" {
		return i.Name
	}
	if i.VulnClass != "" {
		return i.VulnClass
	}
	return "(未命名)"
}

// KindLabel 返回事件类型的短标签，用于消息标题/汇总分组。
func (i Item) KindLabel() string {
	if i.IsFinding() {
		switch i.Kind {
		case EventFindingStatusChanged:
			return "漏洞状态变更"
		case EventFindingRetestReproduced:
			return "复测仍可复现"
		default:
			return "漏洞"
		}
	}
	if label := EventKindLabel(i.Kind); label != "" {
		return label
	}
	return "通知"
}

// DisplayTitle 是渠道正文使用的标题：漏洞状态变更/复测事件带上事件类型前缀，
// 其余漏洞事件保持原样；通用事件也带上事件类型前缀，让不同事件在 IM 里一眼可区分。
func (i Item) DisplayTitle() string {
	switch i.Kind {
	case EventFindingStatusChanged:
		return "漏洞状态变更 · " + i.Title()
	case EventFindingRetestReproduced:
		return "复测仍可复现 · " + i.Title()
	}
	if i.IsFinding() {
		return i.Title()
	}
	label := i.KindLabel()
	if label == "" || strings.HasPrefix(i.Title(), label) {
		return i.Title()
	}
	return label + " · " + i.Title()
}

// Message 是一次渠道发送的完整内容。
type Message struct {
	// 单条推送时长度为 1；汇总推送（digest）时为一整批。
	// 空切片是非法的，调用方须保证至少一条。
	Items []Item
	// Batch=true 时按汇总消息渲染（换标题、带上时间窗与条数）。
	Batch bool
	// WindowMinutes 是汇总周期（分钟），仅 Batch=true 时用于文案「近 N 分钟」。
	// 刻意由配置显式传入而不是渲染时算 time.Since：渲染保持确定性，才好测。
	WindowMinutes int
	// HomeURL 是平台面板地址（全局 public_base_url）；空则不带面板入口。
	HomeURL string
}

// AllFindings 报告整条消息是否只包含漏洞事件。用于保持旧的「漏洞汇总」文案。
func (m Message) AllFindings() bool {
	if len(m.Items) == 0 {
		return false
	}
	for _, it := range m.Items {
		if !it.IsFinding() {
			return false
		}
	}
	return true
}

// KindCount 是汇总消息里的一类事件计数。
type KindCount struct {
	Label string
	Count int
}

// KindCounts 按首次出现顺序统计各类事件数量。
func (m Message) KindCounts() []KindCount {
	var out []KindCount
	index := map[string]int{}
	for _, it := range m.Items {
		label := it.KindLabel()
		if i, ok := index[label]; ok {
			out[i].Count++
			continue
		}
		index[label] = len(out)
		out = append(out, KindCount{Label: label, Count: 1})
	}
	return out
}

// EventKindMeta 是前端「通知内容」开关的数据源。
type EventKindMeta struct {
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	Category    string `json:"category"`
	Default     bool   `json:"default"`
	Description string `json:"description,omitempty"`
}

var eventKindCatalog = []EventKindMeta{
	{Kind: EventFindingCreated, Label: "发现漏洞", Category: "漏洞", Default: true, Description: "新漏洞登记时推送"},
	{Kind: EventFindingStatusChanged, Label: "漏洞状态变更", Category: "漏洞", Default: false, Description: "处置状态流转时推送"},
	{Kind: EventFindingRetestReproduced, Label: "复测仍可复现", Category: "漏洞", Default: true, Description: "复测结论为 reproduced 时推送"},

	{Kind: EventTaskStarted, Label: "任务启动", Category: "任务", Default: false, Description: "任务开始运行时推送"},
	{Kind: EventTaskDone, Label: "任务完成", Category: "任务", Default: true, Description: "任务正常结束/目标达成"},
	{Kind: EventTaskFailed, Label: "任务失败", Category: "任务", Default: true, Description: "任务异常结束"},
	{Kind: EventTaskBlocked, Label: "任务阻塞", Category: "任务", Default: true, Description: "任务进入 blocked 状态"},
	{Kind: EventTaskPaused, Label: "任务暂停", Category: "任务", Default: false, Description: "人工或系统暂停任务"},
	{Kind: EventTaskResumed, Label: "任务恢复", Category: "任务", Default: false, Description: "暂停/阻塞后恢复运行"},
	{Kind: EventTaskTimeout, Label: "任务超时", Category: "任务", Default: true, Description: "任务超过 deadline"},

	{Kind: EventApprovalRequired, Label: "待审批", Category: "审批", Default: true, Description: "工具调用/资产围栏等待人工审批"},

	{Kind: EventReportReady, Label: "报告生成完成", Category: "报告", Default: false, Description: "任务报告生成成功"},
	{Kind: EventReportFailed, Label: "报告生成失败", Category: "报告", Default: true, Description: "任务报告生成失败"},

	{Kind: EventReconNewAssets, Label: "侦察新增资产", Category: "侦察", Default: false, Description: "周期采集发现新资产"},

	{Kind: EventVulnIntelNew, Label: "高危漏洞情报", Category: "漏洞", Default: false, Description: "情报流新增高危/严重漏洞通告"},

	{Kind: EventFingerprintSyncDone, Label: "指纹库更新完成", Category: "规则库", Default: false, Description: "指纹规则同步成功"},
	{Kind: EventFingerprintSyncFailed, Label: "指纹库更新失败", Category: "规则库", Default: true, Description: "指纹规则同步失败"},
	{Kind: EventNucleiUpdateDone, Label: "nuclei 更新完成", Category: "规则库", Default: false, Description: "nuclei 二进制/模板更新成功"},
	{Kind: EventNucleiUpdateFailed, Label: "nuclei 更新失败", Category: "规则库", Default: true, Description: "nuclei 更新失败"},
}

// EventKinds 返回事件类型目录（副本，调用方可安全修改）。
func EventKinds() []EventKindMeta {
	out := make([]EventKindMeta, len(eventKindCatalog))
	copy(out, eventKindCatalog)
	return out
}

// EventKindLabel 返回事件类型的展示标签。
func EventKindLabel(kind string) string {
	for _, m := range eventKindCatalog {
		if m.Kind == kind {
			return m.Label
		}
	}
	return ""
}

// ValidEventKind 报告 kind 是否是已知事件类型。
func ValidEventKind(kind string) bool {
	for _, m := range eventKindCatalog {
		if m.Kind == kind {
			return true
		}
	}
	return false
}

// DefaultEventKinds 返回默认开启的事件类型（新建渠道时的初始勾选）。
func DefaultEventKinds() []string {
	var out []string
	for _, m := range eventKindCatalog {
		if m.Default {
			out = append(out, m.Kind)
		}
	}
	return out
}
