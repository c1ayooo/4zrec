// Package guard 提供执行侧围栏的「目标提取」纯逻辑：从出网类工具的输入里
// 识别真正的出网对象（域名/IP），并标注静态不可判定的 Opaque 形态。
//
// 定位（capkit README 约束「宿主实现端口，capkit 提供可复用实现」）：本包
// 不判授权、不查黑名单、不合成审批——那些是宿主通过 core.Guard 端口做的
// 事。这里只回答一个问题：**这次调用会连到哪里？** 4zrec 与 Cooper 共享
// 同一套「从哪里提目标」的实现，各自决定「提到之后怎么办」。
//
// 实现移植自 4zrec internal/toolface/guard 的四个纯逻辑文件（fence_extract/
// fence_object/fence_http/fence_collector，2026-10-24），对照其测试样例逐条
// 校验（见本包各 _test.go）。已知边界与 4zrec 原版一致，见 cmdrisk.go 与
// fence_object.go 头注释。
package guard

import (
	"encoding/json"
	"fmt"

	"github.com/c1ayooo/4zrec/internal/capkit/core"
)

// fenceTargets 是一次提取出的目标对象集合。Opaque 表示命令会联网、但静态
// 无法确定其实际对象（解释器脚本、未知命令、不可读的目标列表等）；此时
// 调用方必须走审批，而不是因为「没提取到字面目标」就放行。
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

// Result 是 Inspect 的产出：结构化目标 + Opaque 判定。宿主的 Guard 实现拿
// 它做三选一（allow/deny/ask）；core.Target 形态供直接过 scope 判定。
type Result struct {
	// Domains/IPs 是提取出的字面目标（已去重、已归一：域名小写去尾点，
	// IP 变体已归一成点分十进制）。
	Domains []string
	IPs     []string
	// Opaque 表示会联网但静态无法确定完整对象——必须交人工裁决，不允许
	// 因「没提取到目标」而放行。
	Opaque bool
	// Reason 是 Opaque/提取异常的人读理由（给审批卡片与模型看）。
	Reason string
}

// Empty 报告是否既无字面目标也非 Opaque——此时该调用不参与围栏。
func (r Result) Empty() bool { return len(r.Domains) == 0 && len(r.IPs) == 0 && !r.Opaque }

// CoreTargets 把结果转成 capkit 的 Target 形态（Kind+字段，ProjectID 留 0
// 由宿主绑定）。Opaque 时仍返回已提取的字面目标——供审批卡片展示参考。
func (r Result) CoreTargets() []core.Target {
	out := make([]core.Target, 0, len(r.Domains)+len(r.IPs))
	for _, d := range r.Domains {
		t, err := core.TargetFromURL(0, "https://"+d)
		if err != nil {
			continue
		}
		out = append(out, t)
	}
	for _, ip := range r.IPs {
		out = append(out, core.Target{Kind: core.TargetIP, IP: ip})
	}
	return out
}

// Inspect 按工具名从工具输入里提取出网目标。不判授权，只做识别。
// 认识的工具：Bash / shell_open（命令对象解析）、shell_send（字面提取，
// 不按未知命令判 Opaque——往已授权会话里输入不该每条都弹审批）、
// WebFetch（URL 字段）、http_probe（结构化字段：url/requests[].url/
// template×matrix，proxy/headers/body 等字段绝不参与提取）。不认识的
// 工具返回零值 Result——调用方（围栏）按「非出网工具」处理。
// workDir 用于解析 -iL/-l 目标清单文件：只在任务工作目录内的清单可读，
// 目录外或缺失 → Opaque。
func Inspect(tool string, input []byte, workDir string) Result {
	ft := fenceToolTargets(tool, input, workDir)
	return Result{Domains: ft.Domains, IPs: ft.IPs, Opaque: ft.Opaque, Reason: ft.Reason}
}

// Extract 是 Inspect 的便捷形态（工单签名）：无工作目录上下文，Opaque 视为
// 错误——调用方拿到 err 必须走人工裁决，不允许静默放行。
func Extract(tool string, input []byte) ([]core.Target, error) {
	r := Inspect(tool, input, "")
	if r.Opaque {
		return r.CoreTargets(), fmt.Errorf("目标无法静态确定: %s", r.Reason)
	}
	return r.CoreTargets(), nil
}

// ExtractFromCommand 解析一段 shell 命令文本里的出网目标（不经过工具名
// 分派，等价于 Bash 路径）。命令会联网但静态不可判定（解释器脚本、未知
// 命令、不可读清单）时返回错误——fail-closed，交人工裁决。
func ExtractFromCommand(cmd string) ([]core.Target, error) {
	ft := ExtractFenceTargetsWithDir(cmd, "")
	if ft.Opaque {
		return ft2core(ft), fmt.Errorf("目标无法静态确定: %s", ft.Reason)
	}
	return ft2core(ft), nil
}

// ExtractFromURL 从单个 URL 提取 host 目标。按字段结构化取（不做命令
// 解析），供 http_probe 这类工具避免把 header 里的域名误当目标。实现上
// 复用 http_probe 的结构化路径（合成 {"url": …} 输入），语义与
// fence_http.go 完全一致。
func ExtractFromURL(raw string) ([]core.Target, error) {
	ft := extractHTTPProbeTargets([]byte(`{"url":` + jsonString(raw) + `}`))
	if ft.Opaque {
		return ft2core(ft), fmt.Errorf("目标无法静态确定: %s", ft.Reason)
	}
	return ft2core(ft), nil
}

// jsonString 把字符串编码成 JSON 字符串字面量（不带边界引号检查——这就是它）。
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func ft2core(ft fenceTargets) []core.Target {
	return Result{Domains: ft.Domains, IPs: ft.IPs}.CoreTargets()
}
